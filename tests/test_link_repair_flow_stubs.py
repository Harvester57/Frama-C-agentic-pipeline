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
    # Both unreached functions and unreached globals go to link_stubs.c (.bss); no link_globals.c.
    assert repaired == [*sources, fn_file]
    assert not Path(globals_file).exists()
    assert info["stubbed_functions"] == [{"name": "kv_put", "file": "lib/b.c"}]
    assert [g["name"] for g in info["stubbed_globals"]] == ["G_Terminate"]
    assert info["stubbed_globals"][0]["bss"] is True
    assert info["stubbed_globals"][0]["size"] == fuzz_build.DEFAULT_BSS_GLOBAL_SIZE
    assert sorted(info["symbols"]) == ["G_Terminate", "kv_put"]
    text = Path(fn_file).read_text(encoding="utf-8")
    assert b"\r" not in Path(fn_file).read_bytes()
    assert '".globl kv_put\\n"' in text and '"kv_put:\\n"' in text
    assert '".bss\\n"' in text and '".globl G_Terminate\\n"' in text and '"G_Terminate: .zero 16\\n"' in text
    assert "jmp __framac_link_stub_called@PLT" in text
    assert "write(2," in text and "fprintf" not in text
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


def test_build_module_binary_accumulates_residual_function_stubs(tmp_path: Path, monkeypatch) -> None:
    """Residual undefined symbols not pre-seeded accumulate across repair rounds."""
    dag_path = _flow_run_dir(tmp_path)
    # Empty link_stubs so pre-seeding does not cover kv_put/conn_close; repair rounds accumulate them.
    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    dag["submodules"][FLOW_CLUSTER]["link_stubs"] = {"functions": [], "globals": []}
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
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
    assert "preseeded_stubs" not in out
    assert out["sources"] == ["workspace/work/daemon/state.c", fn_file]
    repair = out["link_repair"]
    assert [s["name"] for s in repair["stubbed_functions"]] == ["kv_put", "conn_close"]
    assert repair["functions_file"] == fn_file and "stubbed_globals" not in repair
    assert [r["added_sources"] for r in repair["rounds"]] == [[fn_file], []]
    text = Path(fn_file).read_text(encoding="utf-8")
    assert ".Lframac_link_stub_0" in text and ".Lframac_link_stub_1" in text


def test_c4_preseed_avoids_double_eacsl_instrumentation(tmp_path: Path, monkeypatch) -> None:
    """B9: Attempt-1 pre-seeding writes link_stubs.c up front so compile_eacsl_binary runs once, not twice."""
    dag_path = _flow_run_dir(tmp_path)
    # Attach explicit size to G_Terminate in model.
    model_path = dag_path.parent / "phase0_model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["global_variables"]["daemon/main.c#G_Terminate"]["size"] = 256
    model_path.write_text(json.dumps(model), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    out_bin = Path("workspace/build/fuzz_kvd__c1")
    fn_file = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).as_posix()
    eacsl_calls: list[list[str]] = []

    def fake_eacsl(srcs, out, *a, **k):
        eacsl_calls.append(list(srcs))
        text = Path(fn_file).read_text(encoding="utf-8") if fn_file in srcs else ""
        assert '"kv_put:\\n"' in text and '"conn_close:\\n"' in text
        assert '"G_Terminate: .zero 256\\n"' in text
        return {"engine": "eacsl", "returncode": 0, "binary": str(out)}

    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", fake_eacsl)
    out = R.build_module_binary(
        ["workspace/work/daemon/state.c"],
        out_bin,
        engine="auto",
        apply_selftest=False,
        dag_path=dag_path,
        link_module=FLOW_CLUSTER,
    )
    assert out["compile"]["returncode"] == 0
    assert len(eacsl_calls) == 1
    assert "link_repair" not in out
    assert out["preseeded_stubs"]["functions_file"] == fn_file
    assert [s["name"] for s in out["preseeded_stubs"]["functions"]] == ["conn_close", "kv_put"]
    assert out["preseeded_stubs"]["globals"][0]["size"] == 256


def test_c4_static_collision_build_only_sidecar_sync_and_slice_discovery(tmp_path: Path, monkeypatch) -> None:
    """B4, B7, B8: static clash skipped, build_only linked not stubbed, sidecar flow_build_sources synced, link_stubs excluded."""
    dag_path = _flow_run_dir(tmp_path)
    work = tmp_path / "workspace" / "work"
    (work / "daemon/simd.c").write_text("int simd_fn(void) { return 0; }\n", encoding="utf-8")
    (work / "daemon/a_static.c").write_text("static int clash(void) { return 0; }\n", encoding="utf-8")
    (work / "daemon/z_extern.c").write_text("int clash(void) { return 1; }\n", encoding="utf-8")
    (work / "daemon/global_clash.c").write_text("int g_clash = 7;\n", encoding="utf-8")
    (work / "lib/extlib.c").write_text("int extlib_fn(void) { return 2; }\n", encoding="utf-8")

    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    dag["functions"]["daemon/a_static.c#clash"] = {
        "name": "clash",
        "file": "daemon/a_static.c",
        "module": "kvd",
        "is_static": True,
    }
    dag["functions"]["daemon/z_extern.c#clash"] = {
        "name": "clash",
        "file": "daemon/z_extern.c",
        "module": "kvd",
        "is_static": False,
    }
    dag["functions"]["daemon/a_static.c#g_clash"] = {
        "name": "g_clash",
        "file": "daemon/a_static.c",
        "module": "kvd",
        "is_static": True,
    }
    dag["functions"]["extlib_fn"] = {
        "name": "extlib_fn",
        "file": "lib/extlib.c",
        "module": "libext_a",
        "is_static": False,
    }
    dag["build_only_functions"] = {"daemon/simd.c": ["simd_fn"]}
    dag_path.write_text(json.dumps(dag), encoding="utf-8")

    model_path = dag_path.parent / "phase0_model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["global_variables"]["daemon/global_clash.c#g_clash"] = {
        "name": "g_clash",
        "file": "daemon/global_clash.c",
        "static": False,
        "type": "struct opaque_s",
        "size": 48,
        "units": ["daemon/kvd"],
    }
    model_path.write_text(json.dumps(model), encoding="utf-8")

    # Sidecar widens flow_build_sources with daemon/z_extern.c.
    harnesses = tmp_path / "workspace" / "harnesses"
    harnesses.mkdir(parents=True)
    (harnesses / f"harness_{FLOW_CLUSTER}.json").write_text(
        json.dumps({"module": FLOW_CLUSTER, "flow_build_sources": ["daemon/state.c", "daemon/z_extern.c"]}),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    # _dag_symbol_files skips is_static: `clash` maps to z_extern.c, `g_clash` is not mistaken for a function.
    syms = fuzz_build._dag_symbol_files(dag_path)
    assert syms["clash"] == "daemon/z_extern.c"
    assert "g_clash" not in syms

    # Repair: `clash` is in sidecar flow_build_sources -> linked (not stubbed);
    # `simd_fn` is build_only -> linked (not stubbed);
    # `extlib_fn` is from linked lib not in sub["link_stubs"] -> linked (B1 defense in depth);
    # `g_clash` is a by-value struct global outside flow_files -> .bss stub of 48 bytes in link_stubs.c.
    repaired, info = R.repair_sources_for_link(
        ["workspace/work/daemon/state.c"],
        _undefined_refs("clash", "simd_fn", "extlib_fn", "g_clash"),
        dag_path,
        tmp_path,
        module=FLOW_CLUSTER,
        stub_dir=FLOW_STUB_DIR,
    )
    assert "workspace/work/daemon/z_extern.c" in repaired
    assert "workspace/work/daemon/simd.c" in repaired
    assert "workspace/work/lib/extlib.c" in repaired
    assert "stubbed_functions" not in info
    assert [g["name"] for g in info["stubbed_globals"]] == ["g_clash"]
    stub_text = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).read_text(encoding="utf-8")
    assert '"g_clash: .zero 48\\n"' in stub_text

    # _discover_slice_functions excludes link_stubs.c and __framac_link_stub_called (B4).
    fn_file = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).as_posix()
    discovered = fuzz_build._discover_slice_functions(["workspace/work/daemon/z_extern.c", fn_file])
    assert "clash" in discovered
    assert "__framac_link_stub_called" not in discovered
    assert "__framac_write_all" not in discovered
