"""
End-to-end Docker integration suite for the address-flow unit split (correction plan step C7 item 1).

Executes real C fixtures inside `framac-analysis:latest` (`--rm --network none`) through the real
pipeline path: `phase0_dump.ml` -> `phase0_model.build_model` -> `build_callgraph_dag.build_dag` ->
`generate_harness.generate_module_harness` -> `fuzz_build.build_module_binary` (sanitizers and/or
E-ACSL) -> binary execution -> `run_eva_slice.run_eva_on_slice`.

Covers every counterexample from `docs/plans/archive/unit-split-address-flow-review.md` (CE-1..CE-7) plus
deliberate link-stub abort detection (both ASan and E-ACSL, C4/C5) and deliberate omitted-body Eva
rejection (C6). Opt-in via `FRAMAC_DOCKER_TESTS=1`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

pytestmark = [pytest.mark.integration, pytest.mark.slow]

_DOCKER_TIMEOUT_S = 300

# In-container driver written into each test's `/framac-run/_driver.py`. Runs purely inside
# `framac-analysis:latest` with `/opt/framac-pipeline/{scripts,templates,schemas}` mounted read-only
# and the precompiled `phase0_dump.cmxs` mounted at `/dump-cache`.
_CONTAINER_DRIVER = """\
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/framac-pipeline/scripts")

import build_callgraph_dag  # noqa: E402
import failure_identity  # noqa: E402
import fuzz_build  # noqa: E402
import generate_harness  # noqa: E402
import phase0_model  # noqa: E402
import run_eva_slice  # noqa: E402
import validate_artifacts  # noqa: E402

RUN_DIR = Path("/framac-run")
WORK_DIR = RUN_DIR / "workspace" / "work"
REPORTS_DIR = RUN_DIR / "workspace" / "reports"
HARNESS_DIR = RUN_DIR / "workspace" / "harnesses"
BUILD_DIR = RUN_DIR / "workspace" / "build"
EVA_DIR = RUN_DIR / "workspace" / "eva"
DUMP_CMXS = Path("/dump-cache/phase0_dump.cmxs")


def _run_binary(binary: str, seed_bytes: bytes) -> dict[str, Any]:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    seed_path = BUILD_DIR / "seed.bin"
    seed_path.write_bytes(seed_bytes)
    proc = subprocess.run(
        [binary, str(seed_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    combined = (proc.stdout or "") + "\\n" + (proc.stderr or "")
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "runtime_failure": failure_identity.parse_runtime_failure(combined, binary=binary),
        "link_stub_abort": failure_identity.parse_link_stub_abort(combined),
    }


def _read_optional(path: Path) -> str | None:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None


def _build_and_exec(
    harness: dict[str, Any],
    cluster_mod: str,
    dag_path: Path,
    engines: list[str],
    seed_bytes: bytes,
) -> dict[str, dict[str, Any]]:
    sources = [harness["harness_file"], *harness["sources"]]
    builds: dict[str, dict[str, Any]] = {}
    for engine in engines:
        out_bin = BUILD_DIR / f"fuzz_{cluster_mod}_{engine}"
        res = fuzz_build.build_module_binary(
            sources=sources,
            out_bin=out_bin,
            engine=engine,
            apply_selftest=False,
            cppflags=harness["cppflags"],
            dag_path=dag_path,
            link_module=cluster_mod,
            use_cache=False,
            security_props="none",
        )
        stub_dir = out_bin.parent / f"{out_bin.name}_link_globals"
        comp = res.get("compile") or {}
        entry: dict[str, Any] = {
            "returncode": comp.get("returncode"),
            "engine_used": res.get("engine_used"),
            "engine_fallback_reason": res.get("engine_fallback_reason"),
            "sources": res.get("sources"),
            "preseeded_stubs": res.get("preseeded_stubs"),
            "link_repair": res.get("link_repair"),
            "attempts": res.get("attempts"),
            "compile_stdout": (comp.get("stdout") or "")[-4000:],
            "compile_stderr": (comp.get("stderr") or "")[-4000:],
            "link_stubs_exists": (stub_dir / fuzz_build.LINK_STUBS_FILE).is_file(),
            "link_stubs_text": _read_optional(stub_dir / fuzz_build.LINK_STUBS_FILE),
            "link_globals_exists": (stub_dir / fuzz_build.LINK_GLOBALS_FILE).is_file(),
            "instrumented_c_text": _read_optional(out_bin.with_suffix(".instrumented.c")),
        }
        if comp.get("returncode") == 0 and comp.get("binary"):
            entry["exec"] = _run_binary(str(comp["binary"]), seed_bytes)
        builds[engine] = entry
    return builds


def _run_full_pipeline(spec: dict[str, Any]) -> dict[str, Any]:
    os.chdir(RUN_DIR)
    # Reuse the module-scoped compiled `phase0_dump.cmxs` (compiled from scripts/phase0_dump.ml
    # via the real `phase0_model.compile_dump_module`).
    phase0_model.compile_dump_module = lambda *a, **k: (DUMP_CMXS, "")

    cap_path = REPORTS_DIR / "build_capture.json"
    model_path = REPORTS_DIR / "phase0_model.json"
    dag_path = REPORTS_DIR / "callgraph_dag.json"

    model, model_rc = phase0_model.build_model(cap_path, model_path, jobs_n=1, broker=False, alias=False)
    model_errors = phase0_model.validate_model(model)
    model_path.write_text(json.dumps(model, indent=2) + "\\n", encoding="utf-8")

    capture = json.loads(cap_path.read_text(encoding="utf-8"))
    dag = build_callgraph_dag.build_dag(
        WORK_DIR,
        model,
        capture,
        units=True,
        split_max_functions=int(spec["split_max_functions"]),
        split_max_lines=15000,
    )
    dag_schema_warn = validate_artifacts.schema_warning("callgraph_dag", dag)
    dag_path.write_text(json.dumps(dag, indent=2) + "\\n", encoding="utf-8")

    target_anchor = str(spec["target_anchor"])
    cluster_mod = next(
        (
            name
            for name, sub in sorted((dag.get("submodules") or {}).items())
            if target_anchor in (sub.get("anchors") or [])
        ),
        None,
    )
    result: dict[str, Any] = {
        "model_rc": model_rc,
        "model_status": model.get("status"),
        "model_errors": model_errors,
        "model_functions": model.get("functions"),
        "model_globals": model.get("global_variables"),
        "model_edges": model.get("edges"),
        "model_indirect_sites": model.get("indirect_sites"),
        "dag_schema_warning": dag_schema_warn,
        "dag_submodules": dag.get("submodules"),
        "dag_globals": dag.get("global_variables"),
        "dag_warnings": dag.get("warnings"),
        "cluster_mod": cluster_mod,
    }
    if not cluster_mod:
        return result

    harness = generate_harness.generate_module_harness(
        module_name=cluster_mod,
        sources=list(spec["harness_initial_sources"]),
        header_include=spec.get("harness_header"),
        entry_fn=target_anchor,
        max_input_size=64,
        cppflags=str(spec["harness_cppflags"]),
        out_dir=HARNESS_DIR,
        entry_style="dispatch",
        dispatch_cases=list(spec["dispatch_cases"]),
        unit=str(spec["unit"]),
        auto_prelude=True,
    )
    sidecar_path = HARNESS_DIR / f"harness_{cluster_mod}.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    result["harness"] = harness
    result["sidecar"] = sidecar

    seed_bytes = bytes(spec.get("seed_bytes") or [0, 2, 1, 3])
    engines = list(spec.get("build_engines") or [])
    if engines:
        result["builds"] = _build_and_exec(harness, cluster_mod, dag_path, engines, seed_bytes)

    if spec.get("run_eva"):
        eva_sources = [harness["harness_file"], *harness["sources"]]
        omit_suffix = spec.get("eva_omit_suffix")
        if omit_suffix:
            eva_sources = [s for s in eva_sources if not s.replace("\\\\", "/").endswith(str(omit_suffix))]
        eva_res = run_eva_slice.run_eva_on_slice(
            sources=eva_sources,
            main_fn="eva_main",
            out_dir=EVA_DIR,
            cppflags=harness["cppflags"],
            module=cluster_mod,
            dag_path=dag_path,
            use_cache=False,
            flamegraph=False,
            security_props=None,
        )
        result["eva"] = eva_res
        result["eva_log"] = _read_optional(EVA_DIR / "eva.log") or ""
        result["eva_sources"] = eva_sources
    return result


def _run_manual_stub_hit(spec: dict[str, Any]) -> dict[str, Any]:
    os.chdir(RUN_DIR)
    dag_path = REPORTS_DIR / "callgraph_dag.json"
    cluster_mod = str(spec["cluster_mod"])
    harness = generate_harness.generate_module_harness(
        module_name=cluster_mod,
        sources=list(spec["harness_initial_sources"]),
        header_include=spec.get("harness_header"),
        entry_fn=str(spec["target_anchor"]),
        max_input_size=64,
        cppflags=str(spec["harness_cppflags"]),
        out_dir=HARNESS_DIR,
        entry_style="dispatch",
        dispatch_cases=list(spec["dispatch_cases"]),
        unit=str(spec["unit"]),
        auto_prelude=True,
    )
    seed_bytes = bytes(spec.get("seed_bytes") or [0, 5])
    builds = _build_and_exec(harness, cluster_mod, dag_path, list(spec["build_engines"]), seed_bytes)
    return {"harness": harness, "builds": builds}


def main() -> int:
    spec = json.loads((RUN_DIR / "_spec.json").read_text(encoding="utf-8"))
    mode = spec.get("mode", "full_pipeline")
    out = _run_manual_stub_hit(spec) if mode == "manual_stub_hit" else _run_full_pipeline(spec)
    (RUN_DIR / "_result.json").write_text(json.dumps(out, indent=2) + "\\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
"""


def _docker_run(args: list[str], timeout: int = _DOCKER_TIMEOUT_S) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="module")
def dump_cmxs_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile `scripts/phase0_dump.ml` once per worker inside `framac-analysis:latest`."""
    require_docker_images(ANALYSIS_IMAGE)
    out_dir = tmp_path_factory.mktemp("p0_dump_cmxs")
    cmd = (
        "import sys; from pathlib import Path; "
        "sys.path.insert(0, '/opt/framac-pipeline/scripts'); "
        "import phase0_model; "
        "mod, why = phase0_model.compile_dump_module(Path('/dump-out'), dump_source=phase0_model.DUMP_SOURCE); "
        "assert mod is not None, why; "
        "print(mod)"
    )
    proc = _docker_run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{(ROOT / 'scripts').resolve()}:/opt/framac-pipeline/scripts:ro",
            "-v",
            f"{out_dir.resolve()}:/dump-out",
            "--entrypoint",
            "python3",
            ANALYSIS_IMAGE,
            "-c",
            cmd,
        ],
        timeout=180,
    )
    assert proc.returncode == 0, f"failed to compile phase0_dump.ml:\n{proc.stdout}\n{proc.stderr}"
    assert (out_dir / "phase0_dump.cmxs").is_file()
    return out_dir


def _split_flag_tokens(cppflags: list[str]) -> list[str]:
    tokens: list[str] = []
    for flag in cppflags:
        if flag.startswith("-I") and len(flag) > 2:
            tokens.extend(["-I", flag[2:]])
        else:
            tokens.append(flag)
    return tokens


def _write_fixture_tree(
    run_dir: Path,
    files: dict[str, str],
    units: dict[str, dict[str, Any]],
    *,
    compile_headers: dict[str, list[str]] | None = None,
) -> None:
    """Populate `workspace/work` and `workspace/reports/build_capture.json` for a synthetic target."""
    work = run_dir / "workspace" / "work"
    reports = run_dir / "workspace" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        dest = work / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8", newline="\n")

    headers_map = compile_headers or {}
    compiles: list[dict[str, Any]] = []
    cap_units: dict[str, dict[str, Any]] = {}
    for uname, udef in units.items():
        slug = uname.replace("/", "_").replace(".", "_")
        u_cppflags = list(udef.get("cppflags") or ["-Isrc"])
        flag_tokens = _split_flag_tokens(u_cppflags)
        u_files = list(udef["files"])
        objs: list[str] = []
        for src in u_files:
            obj = f"build/{slug}__{src.replace('/', '_')}.o"
            objs.append(obj)
            rec: dict[str, Any] = {
                "source": src,
                "object": obj,
                "cwd": ".",
                "arguments": ["gcc", *u_cppflags, "-c", src, "-o", obj],
                "flags": flag_tokens,
                "system_flags": [],
            }
            if src in headers_map:
                rec["headers"] = list(headers_map[src])
            compiles.append(rec)
        cap_units[uname] = {
            "kind": udef["kind"],
            "test": False,
            "objects": objs,
            "files": u_files,
            "links": list(udef.get("links") or []),
            "cppflags": u_cppflags,
            "entry_points": list(udef.get("entry_points") or []),
        }

    capture = {
        "status": "ok",
        "generated_at": "2026-11-20T00:00:00Z",
        "scratch": {"tree": "/framac-run/workspace/work"},
        "compiles": compiles,
        "units": cap_units,
    }
    (reports / "build_capture.json").write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8", newline="\n")


def _run_in_analysis_container(run_dir: Path, dump_cmxs_dir: Path, spec: dict[str, Any]) -> dict[str, Any]:
    """Run `_CONTAINER_DRIVER` inside `framac-analysis:latest` and return `_result.json`."""
    (run_dir / "_driver.py").write_text(_CONTAINER_DRIVER, encoding="utf-8", newline="\n")
    (run_dir / "_spec.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8", newline="\n")
    proc = _docker_run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "-e",
            "FRAMAC_CACHE_DIR=/tmp/framac-cache",
            "-v",
            f"{(ROOT / 'scripts').resolve()}:/opt/framac-pipeline/scripts:ro",
            "-v",
            f"{(ROOT / 'templates').resolve()}:/opt/framac-pipeline/templates:ro",
            "-v",
            f"{(ROOT / 'schemas').resolve()}:/opt/framac-pipeline/schemas:ro",
            "-v",
            f"{dump_cmxs_dir.resolve()}:/dump-cache:ro",
            "-v",
            f"{run_dir.resolve()}:/framac-run",
            "-w",
            "/framac-run",
            "--entrypoint",
            "python3",
            ANALYSIS_IMAGE,
            "/framac-run/_driver.py",
        ]
    )
    assert proc.returncode == 0, f"container driver failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    res_path = run_dir / "_result.json"
    assert res_path.is_file(), f"missing _result.json:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(res_path.read_text(encoding="utf-8"))


def _assert_clean_run(build: dict[str, Any], expected_marker: str) -> None:
    assert build["returncode"] == 0, f"build failed:\n{build.get('compile_stdout')}\n{build.get('compile_stderr')}"
    ex = build["exec"]
    combined = f"{ex['stdout']}\n{ex['stderr']}"
    assert ex["returncode"] == 0, f"binary exited {ex['returncode']}:\n{combined}"
    assert "FRAMAC_LINK_STUB_CALLED" not in combined, combined
    assert ex["link_stub_abort"] is None, ex["link_stub_abort"]
    assert expected_marker in combined, f"missing {expected_marker!r} in:\n{combined}"


# ---------------------------------------------------------------------------------------------------
# Counterexamples CE-1 .. CE-7 (docs/plans/archive/unit-split-address-flow-review.md section 1.2)
# ---------------------------------------------------------------------------------------------------


def test_ce1_linked_static_library_direct_and_callback(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-1 / B1: linked static library `libcore.a` called directly and via callback from split `prog`."""
    files = {
        "lib/core.h": ("#ifndef CORE_H\n#define CORE_H\nint lib_compute(int x);\nint lib_cb(int x);\n#endif\n"),
        "lib/core.c": (
            '#include "core.h"\nint lib_compute(int x) { return x + 10; }\nint lib_cb(int x) { return x * 3; }\n'
        ),
        "src/prog.h": ("#ifndef PROG_H\n#define PROG_H\nint api_a(int x);\nint api_b(int x);\n#endif\n"),
        "src/a.c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            '#include "core.h"\n'
            '#include "prog.h"\n'
            "typedef int (*op_fn)(int);\n"
            "static int invoke_op(op_fn fn, int v) { return fn(v); }\n"
            "static int a1(int x) { return lib_compute(x) + invoke_op(lib_cb, x); }\n"
            "static int a2(int x) { return a1(x); }\n"
            "int api_a(int x) {\n"
            "  int r = a2(x);\n"
            "  if (r != (x + 10) + (x * 3)) abort();\n"
            '  printf("CE1_RV=%d\\n", r);\n'
            "  return r;\n"
            "}\n"
        ),
        "src/b.c": (
            '#include "prog.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "int api_b(int x) { return b2(x); }\n"
        ),
    }
    units = {
        "libcore.a": {
            "kind": "static_lib",
            "files": ["lib/core.c"],
            "links": [],
            "cppflags": ["-Ilib"],
            "entry_points": ["lib/core.c#lib_compute", "lib/core.c#lib_cb"],
        },
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/b.c"],
            "links": ["libcore.a"],
            "cppflags": ["-Isrc", "-Ilib"],
            "entry_points": ["src/a.c#api_a", "src/b.c#api_b"],
        },
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 4,
            "unit": "prog",
            "target_anchor": "api_a",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "prog.h",
            "harness_cppflags": "-Iworkspace/work/src -Iworkspace/work/lib",
            "dispatch_cases": ["(void)api_a((int)(fuzz_len > 0 ? fuzz_buf[0] : 2));"],
            "seed_bytes": [0, 2],
            "build_engines": ["sanitizers", "eacsl"],
            "run_eva": True,
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    # Cross-parse address_refs resolved across prog -> libcore.a.
    assert "lib/core.c#lib_cb" in (res["model_functions"]["src/a.c#a1"].get("address_refs") or [])

    cluster_mod = res["cluster_mod"]
    assert cluster_mod is not None
    sub = res["dag_submodules"][cluster_mod]
    assert sub["reach"] == "address_flow"
    assert "lib/core.c" in sub["build_sources"]
    assert "src/a.c" in sub["build_sources"]
    assert "src/b.c" not in sub["build_sources"]
    assert "lib_compute" not in sub["link_stubs"]["functions"]
    assert "lib_cb" not in sub["link_stubs"]["functions"]
    assert "workspace/work/lib/core.c" in res["harness"]["sources"]

    # Sanitizers and E-ACSL both build and execute lib_compute + lib_cb cleanly (2+10 + 2*3 = 18).
    _assert_clean_run(res["builds"]["sanitizers"], "CE1_RV=18")
    _assert_clean_run(res["builds"]["eacsl"], "CE1_RV=18")

    # Eva sees both library function bodies with no missing spec.
    assert res["eva"]["status"] == "ok", res["eva"]
    assert "Neither code nor specification for function lib_compute" not in res["eva_log"]
    assert "Neither code nor specification for function lib_cb" not in res["eva_log"]


def test_ce2_external_library_callback_via_local_and_struct(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-2 / B2: callback stored in local variable or struct passed to external `qsort`."""
    files = {
        "src/ce2.h": (
            "#ifndef CE2_H\n"
            "#define CE2_H\n"
            "int real_cmp(const void *a, const void *b);\n"
            "int api_sort(int x, int y);\n"
            "int api_other(int x);\n"
            "#endif\n"
        ),
        "src/cmp.c": (
            '#include "ce2.h"\n'
            "int real_cmp(const void *a, const void *b) {\n"
            "  int va = *(const int *)a;\n"
            "  int vb = *(const int *)b;\n"
            "  return (va > vb) - (va < vb);\n"
            "}\n"
        ),
        "src/a.c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            '#include "ce2.h"\n'
            "typedef int (*cmp_fn)(const void *, const void *);\n"
            "struct sorter { cmp_fn cmp; };\n"
            "static int run_local_sort(int a, int b) {\n"
            "  int arr[2] = { a > b ? a : b, a > b ? b : a };\n"
            "  cmp_fn cmp = real_cmp;\n"
            "  qsort(arr, 2, sizeof(int), cmp);\n"
            "  if (arr[0] > arr[1]) abort();\n"
            '  printf("CE2_LOCAL=%d,%d\\n", arr[0], arr[1]);\n'
            "  return arr[0];\n"
            "}\n"
            "static int run_struct_sort(void) {\n"
            "  int arr[2] = { 9, 2 };\n"
            "  struct sorter s = { real_cmp };\n"
            "  qsort(arr, 2, sizeof(int), s.cmp);\n"
            "  if (arr[0] != 2 || arr[1] != 9) abort();\n"
            '  printf("CE2_STRUCT=%d,%d\\n", arr[0], arr[1]);\n'
            "  return arr[0];\n"
            "}\n"
            "int api_sort(int x, int y) {\n"
            "  return run_local_sort(x, y) + run_struct_sort();\n"
            "}\n"
        ),
        "src/b.c": (
            '#include "ce2.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "static int b3(int x) { return b2(x) + 1; }\n"
            "int api_other(int x) { return b3(x); }\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/cmp.c", "src/b.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_sort", "src/b.c#api_other"],
        }
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 4,
            "unit": "prog",
            "target_anchor": "api_sort",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce2.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": [
                "(void)api_sort(fuzz_len > 0 ? (int)fuzz_buf[0] : 5, fuzz_len > 1 ? (int)fuzz_buf[1] : 2);"
            ],
            "seed_bytes": [0, 5, 2],
            "build_engines": ["sanitizers", "eacsl"],
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    # Confirm CE-2 shape: address_refs holds real_cmp, with no callback-arg edge to real_cmp.
    assert "src/cmp.c#real_cmp" in res["model_functions"]["src/a.c#run_local_sort"]["address_refs"]
    assert "src/cmp.c#real_cmp" in res["model_functions"]["src/a.c#run_struct_sort"]["address_refs"]
    assert not any(
        e["callee"] == "src/cmp.c#real_cmp" and "callback-arg" in (e.get("sources") or []) for e in res["model_edges"]
    )

    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert "src/cmp.c" in sub["build_sources"]
    assert "real_cmp" not in sub["link_stubs"]["functions"]

    for engine in ("sanitizers", "eacsl"):
        _assert_clean_run(res["builds"][engine], "CE2_LOCAL=2,5")
        assert "CE2_STRUCT=2,9" in res["builds"][engine]["exec"]["stdout"]


def test_ce3_function_pointer_cast_across_signatures(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-3 / B3: function-pointer cast `void(int *)` -> `void(*)(void *)` builds, runs, and Eva sees body."""
    files = {
        "src/ce3.h": (
            "#ifndef CE3_H\n"
            "#define CE3_H\n"
            "void real_cleanup(int *p);\n"
            "int api_cast(int x);\n"
            "int api_other(int x);\n"
            "#endif\n"
        ),
        "src/handler.c": ('#include "ce3.h"\nvoid real_cleanup(int *p) {\n  if (p) {\n    *p = 42;\n  }\n}\n'),
        "src/a.c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            '#include "ce3.h"\n'
            "typedef void (*cleanup_pt)(void *);\n"
            "#ifdef __clang__\n"
            '__attribute__((no_sanitize("function")))\n'
            "#endif\n"
            "static void invoke_cleanup(cleanup_pt fn, void *arg) { fn(arg); }\n"
            "int api_cast(int x) {\n"
            "  int v = x;\n"
            "  cleanup_pt fn = (cleanup_pt)real_cleanup;\n"
            "  invoke_cleanup(fn, &v);\n"
            "  if (v != 42) abort();\n"
            '  printf("CE3_CLEANED=%d\\n", v);\n'
            "  return v;\n"
            "}\n"
        ),
        "src/b.c": (
            '#include "ce3.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "int api_other(int x) { return b2(x); }\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/handler.c", "src/b.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_cast", "src/b.c#api_other"],
        }
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 3,
            "unit": "prog",
            "target_anchor": "api_cast",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce3.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)api_cast((int)fuzz_len);"],
            "seed_bytes": [0, 7],
            "build_engines": ["sanitizers", "eacsl"],
            "run_eva": True,
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    # Confirm CE-3 signature mismatch: indirect call site has zero type-matched candidates.
    assert "src/handler.c#real_cleanup" in res["model_functions"]["src/a.c#api_cast"]["address_refs"]
    cast_sites = [s for s in res["model_indirect_sites"] if s["caller"] == "src/a.c#invoke_cleanup"]
    assert cast_sites and cast_sites[0]["candidates"] == []

    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert "src/handler.c" in sub["build_sources"]
    assert "real_cleanup" not in sub["link_stubs"]["functions"]

    _assert_clean_run(res["builds"]["sanitizers"], "CE3_CLEANED=42")
    _assert_clean_run(res["builds"]["eacsl"], "CE3_CLEANED=42")

    assert res["eva"]["status"] == "ok", res["eva"]
    assert "Neither code nor specification for function real_cleanup" not in res["eva_log"]
    assert "Values at end of function real_cleanup" in res["eva_log"]


def test_ce4_inc_included_global_table_enters_build_sources(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-4 (.inc) / B6: global table defined in `#include "table.inc"` pulls `src/table.c` and runs callback."""
    files = {
        "src/ce4.h": (
            "#ifndef CE4_H\n"
            "#define CE4_H\n"
            "struct ops {\n"
            "  int marker;\n"
            "  int (*cb)(int);\n"
            "};\n"
            "extern const struct ops g_tbl;\n"
            "int h_inc(int x);\n"
            "int api_inc(int x);\n"
            "int api_other(int x);\n"
            "#endif\n"
        ),
        "src/table.inc": "const struct ops g_tbl = { 77, h_inc };\n",
        "src/table.c": '#include "ce4.h"\n#include "table.inc"\n',
        "src/h.c": '#include "ce4.h"\nint h_inc(int x) { return x + 100; }\n',
        "src/a.c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            '#include "ce4.h"\n'
            "static int a_helper(int x) {\n"
            "  if (g_tbl.marker != 77 || g_tbl.cb == 0) abort();\n"
            "  return g_tbl.cb(x) + g_tbl.marker;\n"
            "}\n"
            "int api_inc(int x) {\n"
            "  int r = a_helper(x);\n"
            '  printf("CE4_INC_RV=%d\\n", r);\n'
            "  return r;\n"
            "}\n"
        ),
        "src/b.c": (
            '#include "ce4.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "int api_other(int x) { return b2(x); }\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/table.c", "src/h.c", "src/b.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_inc", "src/b.c#api_other"],
        }
    }
    _write_fixture_tree(tmp_path, files, units, compile_headers={"src/table.c": ["src/ce4.h", "src/table.inc"]})
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 3,
            "unit": "prog",
            "target_anchor": "api_inc",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce4.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)api_inc((int)(fuzz_len > 0 ? fuzz_buf[0] : 5));"],
            "seed_bytes": [0, 5],
            "build_engines": ["sanitizers", "eacsl"],
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    assert res["dag_globals"]["src/table.inc#g_tbl"]["compiled_in"] == ["src/table.c"]

    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert {"src/a.c", "src/h.c", "src/table.c"} <= set(sub["build_sources"])
    assert sub["link_stubs"]["globals"] == []

    for engine in ("sanitizers", "eacsl"):
        build = res["builds"][engine]
        _assert_clean_run(build, "CE4_INC_RV=182")
        assert not build["link_stubs_exists"]
        assert not build["link_globals_exists"]


def test_ce5_nginx_shaped_header_and_by_value_struct_global_bss_stubs(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-5 / B5: non-self-contained header + by-value struct global stubbed via `.bss` in `link_stubs.c`."""
    files = {
        "src/ngx_config.h": (
            "#ifndef NGX_CONFIG_H\n"
            "#define NGX_CONFIG_H\n"
            "typedef long ngx_int_t;\n"
            "struct ngx_module_s {\n"
            "  ngx_int_t ctx_index;\n"
            "  ngx_int_t index;\n"
            "  char name[32];\n"
            "};\n"
            "#endif\n"
        ),
        # Deliberately non-self-contained: uses ngx_int_t without including ngx_config.h.
        "src/ngx_event.h": (
            "#ifndef NGX_EVENT_H\n#define NGX_EVENT_H\nextern ngx_int_t ngx_accept_disabled;\n#endif\n"
        ),
        "src/ce5.h": ("#ifndef CE5_H\n#define CE5_H\nint api_a(int x);\nint api_b(int x);\n#endif\n"),
        "src/globals.c": (
            '#include "ngx_config.h"\n'
            '#include "ngx_event.h"\n'
            '#include "ce5.h"\n'
            "ngx_int_t ngx_accept_disabled = 11;\n"
            'struct ngx_module_s ngx_http_access_module = { 1, 2, "access" };\n'
            "static int b1(int x) {\n"
            "  return x + (int)ngx_accept_disabled + (int)ngx_http_access_module.index;\n"
            "}\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "int api_b(int x) { return b2(x); }\n"
        ),
        "src/a.c": (
            "#include <stdio.h>\n"
            '#include "ngx_config.h"\n'
            '#include "ngx_event.h"\n'
            '#include "ce5.h"\n'
            "extern struct ngx_module_s ngx_http_access_module;\n"
            "static int a1(int x) { return x + 7; }\n"
            "int api_a(int x) {\n"
            "  int r = a1(x);\n"
            '  printf("CE5_OK=%d\\n", r);\n'
            "  return r;\n"
            "}\n"
            "int unreached_in_a(void) {\n"
            "  return (int)ngx_accept_disabled + (int)ngx_http_access_module.ctx_index;\n"
            "}\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/globals.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_a", "src/globals.c#api_b"],
        }
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 3,
            "unit": "prog",
            "target_anchor": "api_a",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce5.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)api_a((int)(fuzz_len > 0 ? fuzz_buf[0] : 3));"],
            "seed_bytes": [0, 3],
            "build_engines": ["sanitizers", "eacsl"],
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    assert res["model_globals"]["src/globals.c#ngx_accept_disabled"]["size"] == 8
    assert res["model_globals"]["src/globals.c#ngx_http_access_module"]["size"] == 48

    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert sub["build_sources"] == ["src/a.c"]
    assert set(sub["link_stubs"]["globals"]) == {
        "src/globals.c#ngx_accept_disabled",
        "src/globals.c#ngx_http_access_module",
    }

    for engine in ("sanitizers", "eacsl"):
        build = res["builds"][engine]
        _assert_clean_run(build, "CE5_OK=10")
        assert not build["link_globals_exists"], f"{engine} should not emit link_globals.c"
        assert build["link_stubs_exists"], f"{engine} should emit .bss stubs in link_stubs.c"
        assert build["link_repair"] is None, f"{engine} should pre-seed stubs on attempt 1 without repair rounds"
        assert build["attempts"] is None, f"{engine} should succeed in a single pass"
        stub_text = build["link_stubs_text"] or ""
        assert '".bss\\n"' in stub_text
        assert '"ngx_accept_disabled: .zero 8\\n"' in stub_text
        assert '"ngx_http_access_module: .zero 48\\n"' in stub_text


def test_ce6_dispatch_case_global_pulls_definer_and_callback(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-6 / B6 / C3: dispatch case `(void)api_use(&g_cfg);` pulls `src/cfg.c` and `src/cb.c`."""
    files = {
        "src/ce6.h": (
            "#ifndef CE6_H\n"
            "#define CE6_H\n"
            "struct cfg {\n"
            "  int magic;\n"
            "  int (*cb)(int);\n"
            "};\n"
            "extern const struct cfg g_cfg;\n"
            "int real_fn(int x);\n"
            "int api_use(const struct cfg *c);\n"
            "int api_other(int x);\n"
            "#endif\n"
        ),
        "src/cb.c": (
            '#include "ce6.h"\n'
            "static int cb_leaf(int x) { return x * 2; }\n"
            "int real_fn(int x) { return cb_leaf(x) + 1; }\n"
        ),
        "src/cfg.c": '#include "ce6.h"\nconst struct cfg g_cfg = { 99, real_fn };\n',
        "src/a.c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            '#include "ce6.h"\n'
            "static int a1(const struct cfg *c) {\n"
            "  if (!c || c->magic != 99 || c->cb == 0) {\n"
            '    printf("CE6_OBSERVED magic=%d fn_null=%d\\n", c ? c->magic : -1, (!c || !c->cb) ? 1 : 0);\n'
            "    abort();\n"
            "  }\n"
            "  int rv = c->cb(20);\n"
            '  printf("CE6_OBSERVED magic=%d fn_null=0 rv=%d\\n", c->magic, rv);\n'
            "  return rv;\n"
            "}\n"
            "int api_use(const struct cfg *c) { return a1(c); }\n"
        ),
        "src/b.c": (
            '#include "ce6.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "int api_other(int x) { return b2(x); }\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/cfg.c", "src/cb.c", "src/b.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_use", "src/b.c#api_other"],
        }
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 3,
            "unit": "prog",
            "target_anchor": "api_use",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce6.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)api_use(&g_cfg);"],
            "seed_bytes": [0, 1],
            "build_engines": ["sanitizers", "eacsl"],
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None

    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert sub["build_sources"] == ["src/a.c"]

    # Harness snippet `&g_cfg` widens sources and persists `flow_build_sources` in sidecar.
    assert {"workspace/work/src/a.c", "workspace/work/src/cfg.c", "workspace/work/src/cb.c"} <= set(
        res["harness"]["sources"]
    )
    assert {"src/a.c", "src/cfg.c", "src/cb.c"} <= set(res["sidecar"].get("flow_build_sources") or [])

    for engine in ("sanitizers", "eacsl"):
        build = res["builds"][engine]
        _assert_clean_run(build, "CE6_OBSERVED magic=99 fn_null=0 rv=41")
        assert not build["link_globals_exists"]


def test_ce7_constructor_in_compiled_file_joins_reach(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """CE-7 / B8: `__attribute__((constructor))` in compiled `.c` file pulls `src/h.c` into reach."""
    files = {
        "src/ce7.h": (
            "#ifndef CE7_H\n#define CE7_H\nint h_ctor(int x);\nint api_ctor(int x);\nint api_other(int x);\n#endif\n"
        ),
        "src/h.c": '#include "ce7.h"\nint h_ctor(int x) { return x + 55; }\n',
        "src/a.c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            '#include "ce7.h"\n'
            "static int (*g_cb)(int) = 0;\n"
            "static void __attribute__((constructor)) reg_ctor(void) { g_cb = h_ctor; }\n"
            "int api_ctor(int x) {\n"
            "  if (g_cb == 0) abort();\n"
            "  int r = g_cb(x);\n"
            '  printf("CE7_CTOR_RV=%d\\n", r);\n'
            "  return r;\n"
            "}\n"
        ),
        "src/b.c": (
            '#include "ce7.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "static int b3(int x) { return b2(x) + 1; }\n"
            "int api_other(int x) { return b3(x); }\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/h.c", "src/b.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_ctor", "src/b.c#api_other"],
        }
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 4,
            "unit": "prog",
            "target_anchor": "api_ctor",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce7.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)api_ctor((int)(fuzz_len > 0 ? fuzz_buf[0] : 5));"],
            "seed_bytes": [0, 5],
            "build_engines": ["sanitizers", "eacsl"],
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    assert res["model_functions"]["src/a.c#reg_ctor"]["constructor"] is True

    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert {"api_ctor", "reg_ctor", "h_ctor"} <= set(sub["functions"])
    assert {"src/a.c", "src/h.c"} <= set(sub["build_sources"])
    assert "h_ctor" not in sub["link_stubs"]["functions"]

    _assert_clean_run(res["builds"]["sanitizers"], "CE7_CTOR_RV=60")
    _assert_clean_run(res["builds"]["eacsl"], "CE7_CTOR_RV=60")


# ---------------------------------------------------------------------------------------------------
# Deliberate reach-miss loud failure tests: link-stub abort (B4/C4/C5) & Eva missing-body gate (C6)
# ---------------------------------------------------------------------------------------------------


def test_deliberate_stub_hit_aborts_cleanly_in_asan_and_eacsl(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """B4 / C4 / C5: calling a stubbed `far_fn` prints FRAMAC_LINK_STUB_CALLED in both ASan and E-ACSL."""
    work = tmp_path / "workspace" / "work"
    reports = tmp_path / "workspace" / "reports"
    (work / "src").mkdir(parents=True)
    reports.mkdir(parents=True)

    (work / "src" / "stub_caller.h").write_text(
        "#ifndef STUB_CALLER_H\n#define STUB_CALLER_H\nint far_fn(int x);\nint call_far(int x);\n#endif\n",
        encoding="utf-8",
        newline="\n",
    )
    (work / "src" / "stub_caller.c").write_text(
        '#include "stub_caller.h"\nint call_far(int x) { return far_fn(x + 1); }\n',
        encoding="utf-8",
        newline="\n",
    )
    (work / "src" / "far.c").write_text(
        '#include "stub_caller.h"\nint far_fn(int x) { return x * 2; }\n',
        encoding="utf-8",
        newline="\n",
    )

    cluster_mod = "prog__stub_caller"
    dag = {
        "module_kind": "link_unit",
        "functions": {
            "call_far": {"name": "call_far", "file": "src/stub_caller.c", "module": "prog", "is_static": False},
            "far_fn": {"name": "far_fn", "file": "src/far.c", "module": "prog", "is_static": False},
        },
        "global_variables": {},
        "modules": {
            "prog": {
                "module": "prog",
                "unit": "prog",
                "files": ["src/stub_caller.c", "src/far.c"],
                "required_sources": ["src/stub_caller.c", "src/far.c"],
                "functions": ["call_far", "far_fn"],
                "linked_modules": [],
            }
        },
        "submodules": {
            cluster_mod: {
                "module": cluster_mod,
                "unit": "prog",
                "kind": "cluster",
                "reach": "address_flow",
                "anchors": ["call_far"],
                "functions": ["call_far"],
                "build_sources": ["src/stub_caller.c"],
                "link_stubs": {"functions": ["far_fn"], "globals": []},
            }
        },
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag, indent=2) + "\n", encoding="utf-8", newline="\n")
    (reports / "phase0_model.json").write_text(
        json.dumps({"global_variables": {}}, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "mode": "manual_stub_hit",
            "cluster_mod": cluster_mod,
            "unit": "prog",
            "target_anchor": "call_far",
            "harness_initial_sources": ["workspace/work/src/stub_caller.c"],
            "harness_header": "stub_caller.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)call_far((int)fuzz_len);"],
            "seed_bytes": [0, 5],
            "build_engines": ["sanitizers", "eacsl"],
        },
    )

    for engine in ("sanitizers", "eacsl"):
        build = res["builds"][engine]
        assert build["returncode"] == 0, f"{engine} build failed:\n{build['compile_stdout']}\n{build['compile_stderr']}"
        assert build["link_stubs_exists"]
        assert '"far_fn:\\n"' in (build["link_stubs_text"] or "")
        ex = build["exec"]
        combined = f"{ex['stdout']}\n{ex['stderr']}"
        assert ex["returncode"] != 0, f"{engine} binary unexpectedly exited 0:\n{combined}"
        assert "FRAMAC_LINK_STUB_CALLED: far_fn" in ex["stderr"], f"{engine} stderr:\n{ex['stderr']}"
        assert "validate_format_string_argument" not in combined, f"{engine} hit E-ACSL format check:\n{combined}"
        assert ex["runtime_failure"] is None, (
            f"{engine} misclassified stub abort as target bug: {ex['runtime_failure']}"
        )
        assert ex["link_stub_abort"] is not None, f"{engine} failed to parse stub abort:\n{combined}"
        assert ex["link_stub_abort"]["symbol"] == "far_fn", ex["link_stub_abort"]

    # Confirm E-ACSL did not instrument `__framac_link_stub_called`.
    inst_c = res["builds"]["eacsl"]["instrumented_c_text"] or ""
    assert "__gen_e_acsl___framac_link_stub_called" not in inst_c


def test_deliberate_omitted_body_eva_rejects_address_flow_gap(dump_cmxs_dir: Path, tmp_path: Path) -> None:
    """C6: omitting a called project function's `.c` file on an `address_flow` cluster fails Eva loudly."""
    files = {
        "src/ce9.h": (
            "#ifndef CE9_H\n#define CE9_H\nint omitted_helper(int x);\nint api_a(int x);\nint api_b(int x);\n#endif\n"
        ),
        "src/omitted.c": '#include "ce9.h"\nint omitted_helper(int x) { return x + 13; }\n',
        "src/a.c": (
            '#include "ce9.h"\nstatic int a1(int x) { return omitted_helper(x); }\nint api_a(int x) { return a1(x); }\n'
        ),
        "src/b.c": (
            '#include "ce9.h"\n'
            "static int b1(int x) { return x + 1; }\n"
            "static int b2(int x) { return b1(x) + 1; }\n"
            "int api_b(int x) { return b2(x); }\n"
        ),
    }
    units = {
        "prog": {
            "kind": "executable",
            "files": ["src/a.c", "src/omitted.c", "src/b.c"],
            "links": [],
            "cppflags": ["-Isrc"],
            "entry_points": ["src/a.c#api_a", "src/b.c#api_b"],
        }
    }
    _write_fixture_tree(tmp_path, files, units)
    res = _run_in_analysis_container(
        tmp_path,
        dump_cmxs_dir,
        {
            "split_max_functions": 3,
            "unit": "prog",
            "target_anchor": "api_a",
            "harness_initial_sources": ["workspace/work/src/a.c"],
            "harness_header": "ce9.h",
            "harness_cppflags": "-Iworkspace/work/src",
            "dispatch_cases": ["(void)api_a((int)fuzz_len);"],
            "build_engines": [],
            "run_eva": True,
            "eva_omit_suffix": "src/omitted.c",
        },
    )

    assert res["model_rc"] == 0 and res["model_status"] == "ok" and res["model_errors"] == []
    assert res["dag_schema_warning"] is None
    sub = res["dag_submodules"][res["cluster_mod"]]
    assert sub["reach"] == "address_flow"
    assert not any(s.endswith("src/omitted.c") for s in res["eva_sources"])
    assert "Neither code nor specification for function omitted_helper" in res["eva_log"]

    eva = res["eva"]
    assert eva["status"] == "analysis_error", eva
    assert eva.get("reason") == "address_flow_missing_body", eva
    bodies = eva.get("missing_project_bodies") or []
    body_names = {
        str(item.get("function") or item.get("name") or "")
        if isinstance(item, dict)
        else (str(item).rpartition("#")[2] or str(item))
        for item in bodies
    }
    assert "omitted_helper" in body_names, f"expected omitted_helper in missing_project_bodies={bodies!r}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
