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
    functions: dict[str, dict[str, object]] = {
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


def test_preseed_recomputes_stubs_for_widened_flow_build_sources(tmp_path: Path, monkeypatch) -> None:
    """When harness sidecar widens flow_build_sources past DAG build_sources, Attempt 1 pre-seeds the widened stubs."""
    work = tmp_path / "workspace" / "work"
    for rel in ("daemon/state.c", "daemon/init.c", "daemon/extra.c", "daemon/dead.c"):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text("int placeholder(void) { return 0; }\n", encoding="utf-8")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    harnesses = tmp_path / "workspace" / "harnesses"
    harnesses.mkdir(parents=True)

    functions: dict[str, dict[str, object]] = {
        "daemon/state.c#entry_fn": {
            "name": "entry_fn",
            "file": "daemon/state.c",
            "module": "kvd",
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/state.c#dead_in_state": {
            "name": "dead_in_state",
            "file": "daemon/state.c",
            "module": "kvd",
            "internal_callees": ["daemon/dead.c#dead_callee"],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/init.c#init_helper": {
            "name": "init_helper",
            "file": "daemon/init.c",
            "module": "kvd",
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/init.c#dead_in_init": {
            "name": "dead_in_init",
            "file": "daemon/init.c",
            "module": "kvd",
            "internal_callees": ["daemon/extra.c#extra_stub_fn"],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": ["daemon/extra.c#g_extra_stub"],
        },
        "daemon/extra.c#extra_stub_fn": {
            "name": "extra_stub_fn",
            "file": "daemon/extra.c",
            "module": "kvd",
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/dead.c#dead_callee": {
            "name": "dead_callee",
            "file": "daemon/dead.c",
            "module": "kvd",
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
    }
    global_variables: dict[str, dict[str, object]] = {
        "daemon/extra.c#g_extra_stub": {
            "name": "g_extra_stub",
            "file": "daemon/extra.c",
            "static": False,
            "size": 64,
            "init_functions": [],
            "init_globals": [],
        }
    }
    dag = {
        "functions": functions,
        "global_variables": global_variables,
        "module_kind": "link_unit",
        "modules": {
            "kvd": {
                "module": "kvd",
                "unit": "daemon/kvd",
                "files": ["daemon/state.c", "daemon/init.c", "daemon/extra.c", "daemon/dead.c"],
                "functions": sorted(functions),
            }
        },
        "submodules": {
            FLOW_CLUSTER: {
                "unit": "kvd",
                "anchors": ["daemon/state.c#entry_fn"],
                "functions": ["daemon/state.c#entry_fn"],
                "reach": "address_flow",
                "build_sources": ["daemon/state.c"],
                "link_stubs": {"functions": ["daemon/dead.c#dead_callee"], "globals": []},
            }
        },
    }
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    (harnesses / f"harness_{FLOW_CLUSTER}.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { init_helper(); entry_fn(); return 0; }\n",
        encoding="utf-8",
    )
    (harnesses / f"harness_{FLOW_CLUSTER}.json").write_text(
        json.dumps({"module": FLOW_CLUSTER, "flow_build_sources": ["daemon/state.c", "daemon/init.c"]}),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    out_bin = Path("workspace/build/fuzz_kvd__c1")
    fn_file = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).as_posix()
    seen_functions: list[list[str] | None] = []

    def fake_eacsl(srcs, out, *a, **k):
        seen_functions.append(k.get("functions"))
        text = Path(fn_file).read_text(encoding="utf-8") if fn_file in srcs else ""
        # Both the original DAG stub AND the widened file's function + .bss global stubs are pre-seeded on Attempt 1.
        assert '"dead_callee:\\n"' in text
        assert '"extra_stub_fn:\\n"' in text
        assert '"g_extra_stub: .zero 64\\n"' in text
        return {"engine": "eacsl", "returncode": 0, "binary": str(out)}

    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", fake_eacsl)
    out = R.build_module_binary(
        [
            "workspace/work/daemon/state.c",
            "workspace/work/daemon/init.c",
            f"workspace/harnesses/harness_{FLOW_CLUSTER}.c",
        ],
        out_bin,
        engine="auto",
        apply_selftest=False,
        dag_path=dag_path,
        link_module=FLOW_CLUSTER,
    )
    assert out["compile"]["returncode"] == 0
    assert "link_repair" not in out
    assert [s["name"] for s in out["preseeded_stubs"]["functions"]] == ["dead_callee", "extra_stub_fn"]
    assert [(g["name"], g["size"]) for g in out["preseeded_stubs"]["globals"]] == [("g_extra_stub", 64)]
    # E-ACSL instrumentation is scoped to reachable cluster + harness-called functions (dead_in_state/dead_in_init excluded).
    assert seen_functions == [["entry_fn", "init_helper"]]


def test_build_module_binary_does_not_rerun_eacsl_after_non_link_compile_error(tmp_path: Path, monkeypatch) -> None:
    """When auto-mode E-ACSL fails with a Stage 2 C compile error (no undefined refs), repair retries stay on sanitizers."""
    dag_path = _flow_run_dir(tmp_path)
    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    dag["submodules"][FLOW_CLUSTER]["link_stubs"] = {"functions": [], "globals": []}
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    out_bin = Path("workspace/build/fuzz_kvd__c1")
    fn_file = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).as_posix()
    eacsl_calls = 0
    san_calls = 0

    def fake_eacsl(srcs, out, *a, **k):
        nonlocal eacsl_calls
        eacsl_calls += 1
        return {
            "engine": "eacsl",
            "returncode": 1,
            "reason": "eacsl_compile_failed",
            "stderr": "instrumented.c:10: error: invalid application of 'alignof' to an incomplete type 'DIR'\n",
        }

    def fake_sanitizer(srcs, out, *a, **k):
        nonlocal san_calls
        san_calls += 1
        text = Path(fn_file).read_text(encoding="utf-8") if fn_file in srcs else ""
        if '"kv_put:\\n"' not in text:
            return {"engine": "sanitizers", "returncode": 1, "stderr": _undefined_refs("kv_put")}
        return {"engine": "sanitizers", "returncode": 0, "binary": str(out)}

    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", fake_eacsl)
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_sanitizer)
    out = R.build_module_binary(
        ["workspace/work/daemon/state.c"],
        out_bin,
        engine="auto",
        apply_selftest=False,
        dag_path=dag_path,
        link_module=FLOW_CLUSTER,
    )
    assert out["compile"]["returncode"] == 0
    assert out["engine_used"] == "sanitizers"
    assert eacsl_calls == 1
    assert san_calls == 2
    assert out["engine_fallback_reason"] == "eacsl_compile_failed"
    assert out["eacsl_compile_attempt"]["returncode"] == 1


def test_header_inline_global_refs_are_preseeded_and_static_header_helpers_excluded_from_flow_functions(
    tmp_path: Path, monkeypatch
) -> None:
    """
    Header `static inline` helpers (nginx `ngx_crc32_update`, `ngx_write_fd`):
    - `link_stubs_for_files` traverses header callees of compiled `.c` files so globals they
      reference (`ngx_crc32_table256`) are pre-seeded on Attempt 1.
    - `_flow_cluster_functions` omits `header` + `is_static` helpers from `-e-acsl-functions`
      (unless they are explicit harness entry points), avoiding Stage 1 `no function` aborts.
    """
    work = tmp_path / "workspace" / "work"
    for rel in ("daemon/state.c", "daemon/crc.c"):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text("int placeholder(void) { return 0; }\n", encoding="utf-8")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)

    functions: dict[str, dict[str, object]] = {
        "daemon/state.c#entry_fn": {
            "name": "entry_fn",
            "file": "daemon/state.c",
            "module": "kvd",
            "internal_callees": ["daemon/util.h#inline_helper"],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/state.c#unreached_in_state": {
            "name": "unreached_in_state",
            "file": "daemon/state.c",
            "module": "kvd",
            "internal_callees": ["daemon/crc.h#crc_update"],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/util.h#inline_helper": {
            "name": "inline_helper",
            "file": "daemon/util.h",
            "header": True,
            "is_static": True,
            "module": "kvd",
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "daemon/crc.h#crc_update": {
            "name": "crc_update",
            "file": "daemon/crc.h",
            "header": True,
            "is_static": True,
            "module": "kvd",
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": ["daemon/crc.c#crc_table256"],
        },
    }
    global_variables: dict[str, dict[str, object]] = {
        "daemon/crc.c#crc_table256": {
            "name": "crc_table256",
            "file": "daemon/crc.c",
            "static": False,
            "size": 1024,
            "init_functions": [],
            "init_globals": [],
        }
    }
    import unit_split

    stubs = unit_split.link_stubs_for_files(
        functions,
        global_variables,
        sorted(functions),
        {"daemon/state.c"},
    )
    assert stubs["globals"] == ["daemon/crc.c#crc_table256"]

    dag = {
        "functions": functions,
        "global_variables": global_variables,
        "module_kind": "link_unit",
        "modules": {
            "kvd": {
                "module": "kvd",
                "unit": "daemon/kvd",
                "files": ["daemon/state.c", "daemon/crc.c"],
                "functions": sorted(functions),
            }
        },
        "submodules": {
            FLOW_CLUSTER: {
                "unit": "kvd",
                "anchors": ["daemon/state.c#entry_fn"],
                "functions": ["daemon/state.c#entry_fn", "daemon/util.h#inline_helper"],
                "reach": "address_flow",
                "build_sources": ["daemon/state.c"],
                "link_stubs": stubs,
            }
        },
    }
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    scoped = fuzz_build._flow_cluster_functions(dag_path, FLOW_CLUSTER, ["workspace/work/daemon/state.c"])
    assert scoped == ["entry_fn"]
    assert "inline_helper" not in (scoped or [])
