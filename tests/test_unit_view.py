"""Link units as DAG modules (step I5b): build_callgraph_dag.unit_view and scripts/module_map.py."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_callgraph_dag as bcd  # noqa: E402
import module_map  # noqa: E402

pytestmark = pytest.mark.unit

T1A = "Tier 1A (Binary Parser)"
T2 = "Tier 2 (Heap/Tree Parser)"
T3 = "Tier 3 (Internal State / Glue Module)"


def _fn(module: str, file: str, *, static: bool = False, callees: list[str] | None = None) -> dict:
    return {
        "module": module,
        "file": file,
        "is_static": static,
        "internal_callees": callees or [],
        "external_callees": [],
    }


def _lexer_dag() -> dict:
    """The I5a view: lexer modules `decode`, `encode`, `util` (in the library) and `tool` (an executable)."""
    functions = {
        "dec_run": _fn("decode", "src/decode.c", callees=["dec_step", "u_len"]),
        "dec_step": _fn("decode", "src/decode.c", static=True),
        "enc_run": _fn("encode", "src/encode.c", callees=["u_len"]),
        "u_len": _fn("util", "src/util.c"),
        "main": _fn("tool", "tools/main.c", callees=["dec_run"]),
        "t_case": _fn("tests", "tests/t.c"),
    }
    modules = {
        "decode": {"tier": T1A, "cppflags": ["-DDEC"], "run_eva": True, "run_eacsl_fuzz": True, "run_wp_full": True},
        "encode": {"tier": T2, "cppflags": ["-DENC"], "run_eva": True, "run_eacsl_fuzz": True, "run_wp_full": False},
        "util": {"tier": T3, "cppflags": [], "run_eva": True, "run_eacsl_fuzz": False, "run_wp_full": False},
        "tool": {"tier": T3, "cppflags": [], "run_eva": True, "run_eacsl_fuzz": False, "run_wp_full": False},
        "tests": {"tier": T3, "cppflags": [], "run_eva": True, "run_eacsl_fuzz": False, "run_wp_full": False},
    }
    for name, mod in modules.items():
        mod["module"] = name
        mod["functions"] = sorted(k for k, f in functions.items() if f["module"] == name)
    return {"functions": functions, "modules": modules}


def _model() -> dict:
    def mf(file: str, name: str) -> dict:
        return {"file": file, "name": name}

    return {
        "functions": {
            "src/decode.c#dec_run": mf("src/decode.c", "dec_run"),
            "src/decode.c#dec_step": mf("src/decode.c", "dec_step"),
            "src/encode.c#enc_run": mf("src/encode.c", "enc_run"),
            "src/util.c#u_len": mf("src/util.c", "u_len"),
            "tools/main.c#main": mf("tools/main.c", "main"),
            "tests/t.c#t_case": mf("tests/t.c", "t_case"),
        },
        "units": {
            # Listed executable-first to check that libraries own shared files.
            "kvtool": {
                "kind": "executable",
                "files": ["tools/main.c"],
                "links": ["lib/libkv.a"],
                "entry_points": ["tools/main.c#main"],
                "cppflags": ["-DTOOL"],
            },
            "lib/libkv.a": {
                "kind": "static_lib",
                "files": ["src/decode.c", "src/encode.c", "src/util.c"],
                "entry_points": ["src/decode.c#dec_run", "src/encode.c#enc_run", "src/util.c#u_len"],
                "cppflags": ["-DLIB"],
                "concurrent": True,
            },
            "kvtest": {"kind": "executable", "test": True, "files": ["tests/t.c"], "links": ["lib/libkv.a"]},
        },
    }


def _units() -> dict:
    return bcd.unit_view(_lexer_dag(), _model())


def test_unit_module_names_are_make_safe() -> None:
    assert bcd.unit_module_name("lib/libkv.a") == "libkv_a"
    assert bcd.unit_module_name("out/libcryptolib.so") == "libcryptolib_so"
    assert bcd.unit_module_name("tune") == "tune_unit"


def test_unit_cppflags_are_single_tokens() -> None:
    flags, forced = bcd.unit_cppflags(
        ["-DA", "-I", "inc", "-include", "config.h", "-isystem", "sys", "-std=c99", "-I", "inc"],
        ["-Ilex", "-DLEGACY", "-Iinc"],
    )
    assert flags == ["-DA", "-Iinc", "-Isys", "-std=c99", "-Ilex"]
    assert forced == ["config.h"]
    # Rooted like the lexer's flags (relative to the run directory).
    flags, forced = bcd.unit_cppflags(
        ["-include", "config.h", "-I", "include", "-Ilib", "-I.", "-I/usr/inc"],
        ["-Iworkspace/work/lib"],
        "workspace/work",
    )
    assert flags == ["-Iworkspace/work/include", "-Iworkspace/work/lib", "-Iworkspace/work", "-I/usr/inc"]
    assert forced == ["workspace/work/config.h"]


def test_harness_sources_follow_the_callees_lexer_module(tmp_path: Path) -> None:
    import generate_harness

    (tmp_path / "reports").mkdir()
    (tmp_path / "harnesses").mkdir()
    dag = {
        "module_kind": "link_unit",
        "functions": {"u_len": {"module": "libkv_a", "lexer_module": "util", "file": "src/util.c"}},
        "modules": {"libkv_a": {"required_sources": ["src/util.c", "src/decode.c", "src/fc_main.c"]}},
        "lexer_modules": {"util": {"required_sources": ["src/util.c", "src/str.c"]}},
    }
    (tmp_path / "reports/callgraph_dag.json").write_bytes(json.dumps(dag).encode())
    merged = generate_harness._merge_dag_harness_sources(tmp_path / "harnesses", ["src/harness_util.c"], False, "u_len")
    assert merged == ["src/harness_util.c", "src/util.c", "src/str.c"]


def test_harness_flags_take_the_units_force_includes(tmp_path: Path) -> None:
    import generate_harness

    (tmp_path / "reports").mkdir()
    (tmp_path / "harnesses").mkdir()
    dag = {
        "module_kind": "link_unit",
        "modules": {
            "libtlv_a": {"cppflags": ["-Iworkspace/work/include"], "force_includes": ["workspace/work/config.h"]}
        },
        "unit_of_lexer_module": {"tlv": "libtlv_a"},
        "lexer_modules": {"tlv": {"cppflags": ["-DLEGACY"]}},
    }
    (tmp_path / "reports/callgraph_dag.json").write_bytes(json.dumps(dag).encode())
    for module in ("libtlv_a", "tlv"):
        flags = generate_harness._merge_dag_module_cppflags(module, tmp_path / "harnesses", "-I.")
        assert flags.split() == ["-I.", "-Iworkspace/work/include", "-include", "workspace/work/config.h"]
    again = generate_harness._merge_dag_module_cppflags(
        "tlv", tmp_path / "harnesses", "-include workspace/work/config.h"
    )
    assert again.count("config.h") == 1
    # The spec's own quoted flag keeps its quoting; the build's quoted macro (CryptoLib's
    # -DMC_LOG_PATH="log.txt", which later stages would unquote) and its -std= are not carried over.
    modules: dict = dag["modules"]  # type: ignore[assignment]
    modules["libtlv_a"]["cppflags"] = ['-DLOG="log.txt"', "-std=c89", "-DN=4"]
    (tmp_path / "reports/callgraph_dag.json").write_bytes(json.dumps(dag).encode())
    merged = generate_harness._merge_dag_module_cppflags("tlv", tmp_path / "harnesses", "-DA='x y'")
    assert generate_harness._split_cppflags(merged)[:2] == ["-DA=x y", "-DN=4"]


def test_modules_are_the_non_test_link_units() -> None:
    dag = _units()
    assert dag["module_kind"] == "link_unit"
    assert list(dag["modules"]) == ["libkv_a", "kvtool", "tests"]  # libraries first; test code keeps its module
    lib, tool = dag["modules"]["libkv_a"], dag["modules"]["kvtool"]
    assert lib["unit"] == "lib/libkv.a" and lib["kind"] == "static_lib" and lib["concurrent"]
    assert lib["functions"] == ["dec_run", "dec_step", "enc_run", "u_len"]
    assert lib["lexer_modules"] == ["decode", "encode", "util"]
    assert lib["candidate_entry_points"] == ["dec_run", "enc_run", "u_len"]
    # The build's flags only: the lexer's Makefile -D flags can contradict them.
    assert lib["cppflags"] == ["-DLIB"] and lib["force_includes"] == []
    # The most demanding tier and run flags of its lexer modules.
    assert lib["tier"] == T1A and lib["run_wp_full"] and lib["run_eacsl_fuzz"]
    # An executable needs the sources of the libraries it links.
    assert tool["functions"] == ["main"] and tool["candidate_entry_points"] == ["main"]
    assert tool["required_sources"] == ["tools/main.c", "src/decode.c", "src/encode.c", "src/util.c"]
    assert tool["files"] == ["tools/main.c"]
    assert "dec_run" in tool["cross_module_callees"]


def test_functions_keep_their_lexer_module_and_tier() -> None:
    dag = _units()
    enc = dag["functions"]["enc_run"]
    assert enc["module"] == "libkv_a" and enc["lexer_module"] == "encode" and enc["tier"] == T2
    assert dag["functions"]["t_case"]["module"] == "tests"
    every = sorted(k for m in dag["modules"].values() for k in m["functions"])
    assert every == sorted(dag["functions"])
    assert dag["unit_of_lexer_module"] == {
        "decode": "libkv_a",
        "encode": "libkv_a",
        "tool": "kvtool",
        "util": "libkv_a",
    }
    assert set(dag["lexer_modules"]) == {"decode", "encode", "util", "tool", "tests"}


def test_without_units_the_dag_is_unchanged() -> None:
    dag = _lexer_dag()
    assert bcd.unit_view(copy.deepcopy(dag), {"units": {}}) == dag


def _sidecars() -> dict[str, dict]:
    return {
        "decode": {"unit": "libkv_a", "sources": ["src/decode.c"]},
        "encode": {"unit": "libkv_a", "sources": ["src/encode.c"]},
        "kvtool": {"sources": ["tools/main.c"]},
        "extra": {"unit": "libkv_a", "scope_files": ["workspace/work/src/util.c"]},
    }


def test_module_map_resolves_sub_modules_to_their_unit() -> None:
    mm = module_map.ModuleMap(_units(), _sidecars())
    assert mm.units_are_link_units
    assert mm.unit_of("decode") == "libkv_a" and mm.unit_of("kvtool") == "kvtool"
    assert mm.unit_of("util") == "libkv_a"  # no sidecar: through the lexer module
    assert mm.unit_of("nowhere") == "nowhere"
    assert mm.same_unit("decode", "encode") and not mm.same_unit("decode", "kvtool")
    assert mm.submodules("libkv_a") == ["decode", "encode", "extra"]
    assert mm.harness_module_for("libkv_a") == "decode" and mm.harness_module_for("kvtool") == "kvtool"
    assert mm.harness_module_for("tests") is None
    assert mm.is_submodule("decode") and not mm.is_submodule("kvtool")


def test_module_map_scope_tier_and_flags() -> None:
    mm = module_map.ModuleMap(_units(), _sidecars())
    assert mm.scope_functions("decode") == ["dec_run", "dec_step"]
    assert mm.scope_functions("extra") == ["u_len"]  # from scope_files
    assert mm.scope_functions("kvtool") == ["main"]
    assert mm.scope_entry_points("encode") == ["enc_run"]
    assert mm.scope_entry_points("kvtool") == ["main"]
    assert mm.tier_of("encode") == T2 and mm.tier_of("extra") == T1A
    assert mm.run_flags("encode") == {"run_eva": True, "run_eacsl_fuzz": True, "run_wp_full": False}
    assert mm.run_flags("decode")["run_wp_full"]
    assert mm.unit_record("encode")["unit"] == "lib/libkv.a"


def test_module_map_is_the_identity_without_link_units() -> None:
    dag = _lexer_dag()
    mm = module_map.ModuleMap(dag, {"decode": {"sources": ["src/decode.c"]}})
    assert not mm.units_are_link_units
    for m in ("decode", "encode", "tool", "unknown"):
        assert mm.unit_of(m) == m
    assert mm.submodules("decode") == ["decode"] and not mm.is_submodule("decode")
    assert mm.scope_functions("decode") == ["dec_run", "dec_step"]
    assert mm.tier_of("encode") == T2
    assert module_map.infer_unit(dag, "decode") is None


def test_infer_unit() -> None:
    dag = _units()
    assert module_map.infer_unit(dag, "kvtool") == "kvtool"
    assert module_map.infer_unit(dag, "encode") == "libkv_a"
    assert module_map.infer_unit(dag, "fresh", ["main", "dec_run", "u_len"]) == "libkv_a"
    assert module_map.infer_unit(dag, "fresh", []) is None


def test_module_map_load(tmp_path: Path) -> None:
    (tmp_path / "workspace/reports").mkdir(parents=True)
    (tmp_path / "workspace/harnesses").mkdir(parents=True)
    (tmp_path / "workspace/reports/callgraph_dag.json").write_bytes(json.dumps(_units()).encode())
    (tmp_path / "workspace/harnesses/harness_encode.json").write_bytes(json.dumps({"unit": "libkv_a"}).encode())
    (tmp_path / "workspace/harnesses/harness_bad.json").write_bytes(b"{not json")
    mm = module_map.ModuleMap.load(tmp_path)
    assert list(mm.sidecars) == ["encode"]
    assert mm.submodules("libkv_a") == ["encode"]
