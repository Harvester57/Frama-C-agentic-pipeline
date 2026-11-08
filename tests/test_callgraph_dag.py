"""Tests for scripts/build_callgraph_dag.py: waves, and the per-function facts it derives from the model."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import build_callgraph_dag as bcd

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_callgraph_dag.py"


def test_tarjan_scc_waves_and_mutual_recursion() -> None:
    functions = {
        "leaf": {"self_recursive": False},
        "mid": {"self_recursive": False},
        "top": {"self_recursive": False},
        "cycle_a": {"self_recursive": False},
        "cycle_b": {"self_recursive": False},
        "self_rec": {"self_recursive": True},
    }
    call_edges = {
        "leaf": set(),
        "mid": {"leaf"},
        "top": {"mid", "cycle_a"},
        "cycle_a": {"cycle_b", "leaf"},
        "cycle_b": {"cycle_a"},
        "self_rec": {"leaf"},
    }
    waves, cycles = bcd.compute_topological_waves(functions, call_edges)
    wave_of = {fn: idx for idx, w in enumerate(waves) for fn in w}
    assert wave_of["leaf"] == 0
    assert wave_of["mid"] == 1
    assert wave_of["cycle_a"] == wave_of["cycle_b"]
    assert wave_of["top"] > wave_of["cycle_a"]
    assert ["cycle_a", "cycle_b"] in cycles
    assert ["self_rec"] in cycles


@pytest.mark.parametrize(
    "sig,expected",
    [
        ("int(void)", ("int", [], False)),
        ("int()", ("int", [], False)),
        ("void(char *,unsigned long)", ("void", ["char *", "unsigned long"], False)),
        ("int(int,...)", ("int", ["int"], True)),
        # A function pointer parameter keeps its own parentheses and commas.
        (
            "void(struct q (*)(void *p, unsigned long n),void *)",
            ("void", ["struct q (*)(void *p, unsigned long n)", "void *"], False),
        ),
        # A function returning a function pointer: the last group is the parameter list.
        ("int (*)(int)(char)", ("int (*)(int)", ["char"], False)),
        ("", ("", [], False)),
    ],
)
def test_split_signature(sig: str, expected: tuple) -> None:
    assert bcd.split_signature(sig) == expected


def _formals(*kinds: str) -> list[dict]:
    return [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)]


def test_signature_facts_with_formals() -> None:
    parser = bcd.signature_facts(
        {"signature": "int(unsigned char *,unsigned long)", "formals": _formals("const_pointer", "value")}
    )
    assert parser["const_ptr_params"] == 1 and parser["mutable_ptr_params"] == 0
    assert parser["takes_bounded_buffer"] and not parser["writes_bounded_buffer"]
    emitter = bcd.signature_facts(
        {"signature": "int(char *,unsigned long,char *)", "formals": _formals("pointer", "value", "const_pointer")}
    )
    assert emitter["writes_bounded_buffer"] and emitter["takes_bounded_buffer"]
    # A struct pointer is not a byte buffer; a pointer to an array is a pointer, not a function pointer.
    other = bcd.signature_facts(
        {"signature": "void(struct s *,long (*)[16],int (*)(int))", "formals": _formals("pointer", "pointer", "value")}
    )
    assert other["mutable_ptr_params"] == 2 and not other["writes_bounded_buffer"]
    assert other["params"] == ["struct s *", "long (*)[16]", "int (*)(int)"]
    # A pointer to pointers (an advanced cursor) is not a byte buffer either.
    cursor = bcd.signature_facts({"signature": "void(char **,unsigned long)", "formals": _formals("pointer", "value")})
    assert cursor["mutable_ptr_params"] == 1 and not cursor["writes_bounded_buffer"]
    getter = bcd.signature_facts({"signature": "struct iface *(void)", "formals": []})
    assert getter["returns_pointer"] and getter["params"] == []


def test_signature_facts_see_frama_cs_variadic_translation() -> None:
    rec = {"signature": "_Bool(char *,char *,void **)", "formals": [*_formals("pointer", "const_pointer")]}
    rec["formals"].append({"name": bcd.VA_PARAMS, "kind": "pointer"})
    facts = bcd.signature_facts(rec)
    assert facts["is_variadic"] and facts["params"] == ["char *", "char *"]
    assert bcd.signature_facts({"signature": "int(int,...)"})["is_variadic"]


def test_signature_facts_without_formals_guess_no_buffer_direction() -> None:
    facts = bcd.signature_facts({"signature": "int(char *,unsigned long)"})
    assert facts["mutable_ptr_params"] == 1 and facts["const_ptr_params"] == 0
    assert not facts["takes_bounded_buffer"] and not facts["writes_bounded_buffer"]


def test_call_and_wp_facts() -> None:
    calls = bcd.call_facts({"external_calls": ["memcpy", "malloc", "puts"]}, ["ctx->cb"])
    assert calls["has_dynamic_alloc"] and calls["uses_format_or_write"]
    assert calls["external_callees"] == ["malloc", "memcpy", "puts"]
    rec = {**bcd.signature_facts({"signature": "int(int,...)"}), **calls}
    wp = bcd.wp_facts("log_it", rec)
    assert wp["wp_blockers"] == ["internal_variadic", "dynamic_allocation"]
    assert wp["verifiability"] == "shell_unverifiable_wp"
    assert any("ctx->cb" in n for n in wp["wp_notes"])
    plain = {**bcd.signature_facts({"signature": "int(int)"}), **bcd.call_facts({}, ["fp"])}
    assert bcd.wp_facts("f", plain)["verifiability"] == "needs_calls_annotation"
    harness = bcd.wp_facts("LLVMFuzzerTestOneInput", {**plain, "indirect_calls": []})
    assert harness["wp_blockers"] == ["fuzz_or_eva_harness_entrypoint"]


def test_termination_properties() -> None:
    assert [p["template"] for p in bcd.termination_properties({"has_loops": True, "loop_count": 2})] == ["loop variant"]
    assert [p["template"] for p in bcd.termination_properties({"is_recursive": True})] == ["decreases"]
    assert bcd.termination_properties({}) == []
    assert all(p["layer"] == 2 for p in bcd.termination_properties({"has_loops": True}))


@pytest.mark.parametrize(
    "path,module",
    [
        ("src/decode/ber.c", "decode"),
        ("src/decode/sub/x.c", "decode"),
        ("src/util.c", "util"),
        ("lib/x.c", "lib"),
        ("minmea.c", "minmea"),
    ],
)
def test_path_module(path: str, module: str) -> None:
    assert bcd.path_module(path) == module


def test_include_dirs_come_from_sources_and_their_headers() -> None:
    capture = {
        "compiles": [
            {"source": "src/a.c", "headers": ["inc/qcbor/qcbor.h", "inc/qcbor/common.h", "src/local.h"]},
            {"source": "src/a.c", "headers": ["cfg/config.h"]},
            {"source": "main.c", "headers": []},
        ]
    }
    assert bcd.include_dirs(["src/a.c", "main.c"], capture) == ["src", "cfg", "inc/qcbor", ""]
    assert bcd.include_dirs(["src/a.c"], None) == ["src"]


def _model() -> dict:
    fn = {"line": 1, "end_line": 3, "lines": 3, "loops": 0, "cyclomatic": 1, "source": "frama-c-kernel"}
    return {
        "status": "ok",
        "units": {"libx.a": {"kind": "static_lib", "files": ["x.c"], "cppflags": ["-DX"], "entry_points": ["x.c#f"]}},
        "functions": {"x.c#f": {**fn, "file": "x.c", "name": "f", "signature": "int(int)", "units": ["libx.a"]}},
        "edges": [],
        "entry_points": ["x.c#f"],
    }


def test_cli_without_a_model_stops(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--target", str(tmp_path), "--out", str(tmp_path / "dag.json"),
         "--model", str(tmp_path / "missing.json")],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert proc.returncode == 2 and "needs_build_recipe" in proc.stderr
    assert not (tmp_path / "dag.json").exists()


def test_cli_writes_the_dag_with_the_capture_next_to_the_model(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "phase0_model.json").write_text(json.dumps(_model()), encoding="utf-8")
    capture = {"status": "ok", "compiles": [{"source": "x.c", "headers": ["inc/x.h"]}]}
    (reports / "build_capture.json").write_text(json.dumps(capture), encoding="utf-8")
    (tmp_path / "work").mkdir()
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--target", str(tmp_path / "work"), "--out", str(tmp_path / "dag.json"),
         "--model", str(reports / "phase0_model.json")],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    dag = json.loads((tmp_path / "dag.json").read_text(encoding="utf-8"))
    assert dag["module_kind"] == "link_unit" and len(dag["modules"]) == 1
    (name,) = dag["modules"]
    root = (tmp_path / "work").resolve().as_posix()
    assert dag["modules"][name]["cppflags"] == ["-DX", f"-I{root}", f"-I{root}/inc"]
    assert dag["unit_of_lexer_module"] == {"x": name}
    assert dag["tiers"]["source"] == "structure"
