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
import tiers  # noqa: E402

pytestmark = pytest.mark.unit

T1A, T2, T3 = tiers.TIER_1A, tiers.TIER_2, tiers.TIER_3
# The tiers the step I8 rules would give; set by hand so that these tests only exercise the views.
TIERS = {"dec_run": T1A, "dec_step": T1A, "enc_run": T2, "u_len": T3, "main": T3, "t_case": T3}


def _model() -> dict:
    """Path modules `decode`, `encode`, `util` (in the library), `tools` (an executable) and `tests`."""

    def mf(file: str, name: str, line: int, static: bool = False) -> dict:
        return {
            "file": file,
            "name": name,
            "line": line,
            "end_line": line + 2,
            "lines": 3,
            "static": static,
            "loops": 0,
            "cyclomatic": 1,
            "signature": "int(int)",
            "source": "frama-c-kernel",
            "units": [UNIT_OF[file]],
        }

    def edge(caller: str, callee: str) -> dict:
        return {"caller": caller, "callee": callee, "kind": "direct"}

    return {
        "status": "ok",
        "functions": {
            "src/decode.c#dec_run": mf("src/decode.c", "dec_run", 1),
            "src/decode.c#dec_step": mf("src/decode.c", "dec_step", 5, static=True),
            "src/encode.c#enc_run": mf("src/encode.c", "enc_run", 1),
            "src/util.c#u_len": mf("src/util.c", "u_len", 1),
            "tools/main.c#main": mf("tools/main.c", "main", 1),
            "tests/t.c#t_case": mf("tests/t.c", "t_case", 1),
        },
        "edges": [
            edge("src/decode.c#dec_run", "src/decode.c#dec_step"),
            edge("src/decode.c#dec_run", "src/util.c#u_len"),
            edge("src/encode.c#enc_run", "src/util.c#u_len"),
            edge("tools/main.c#main", "src/decode.c#dec_run"),
        ],
        "entry_points": ["tools/main.c#main"],
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


UNIT_OF = {
    "src/decode.c": "lib/libkv.a",
    "src/encode.c": "lib/libkv.a",
    "src/util.c": "lib/libkv.a",
    "tools/main.c": "kvtool",
    "tests/t.c": "kvtest",
}


def _tiered(dag: dict) -> dict:
    for key, rec in dag["functions"].items():
        rec["tier"] = TIERS[key]
    return tiers.retier_modules(dag)


def _path_dag() -> dict:
    """The I5a view: path modules as the modules."""
    return _tiered(bcd.model_view(_model()))


def _units() -> dict:
    return _tiered(bcd.unit_view(bcd.model_view(_model()), _model()))


def test_unit_module_names_are_make_safe() -> None:
    assert bcd.unit_module_name("lib/libkv.a") == "libkv_a"
    assert bcd.unit_module_name("out/libcryptolib.so") == "libcryptolib_so"
    assert bcd.unit_module_name("tune") == "tune_unit"


def test_unit_cppflags_are_single_tokens() -> None:
    flags, forced = bcd.unit_cppflags(
        ["-DA", "-I", "inc", "-include", "config.h", "-isystem", "sys", "-std=c99", "-I", "inc"],
        ["src", "inc"],
    )
    assert flags == ["-DA", "-Iinc", "-Isys", "-std=c99", "-Isrc"]
    assert forced == ["config.h"]
    # Rooted at the DAG's target directory (relative to the run directory).
    flags, forced = bcd.unit_cppflags(
        ["-include", "config.h", "-I", "include", "-Ilib", "-I.", "-I/usr/inc"],
        ["lib", ""],
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
    # The build's flags, then the sources' directories (no capture here, so no header directories).
    assert lib["cppflags"] == ["-DLIB", "-Isrc"] and lib["force_includes"] == []
    # The most demanding tier and run flags of its functions.
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
        "tools": "kvtool",
        "util": "libkv_a",
    }
    assert set(dag["lexer_modules"]) == {"decode", "encode", "util", "tools", "tests"}


def test_without_units_the_dag_is_unchanged() -> None:
    dag = _path_dag()
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
    assert mm.unit_of("util") == "libkv_a"  # no sidecar: through the path module
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
    dag = _path_dag()
    mm = module_map.ModuleMap(dag, {"decode": {"sources": ["src/decode.c"]}})
    assert not mm.units_are_link_units
    for m in ("decode", "encode", "tools", "unknown"):
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
