"""The call-graph DAG built from the Phase 0 model (step I5a): build_callgraph_dag.model_view,
the ledger seed's use of it, and the macro aliases in harness_reach."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_callgraph_dag as bcd  # noqa: E402
import harness_reach  # noqa: E402

pytestmark = pytest.mark.unit

A_C = """\
#include "h.h"
static int helper(int x) { return x + 1; }
static int cb(int v) { return v; }
int api_run(int n) {
    int (*fp)(int) = cb;
    int s = 0;
    for (int i = 0; i < n; i++) s += helper(i);
    return s + fp(n) + hin(n);
}
"""
B_C = """\
static int helper(int x) { return x * 2; }
int api_other(int x) { return helper(x); }
"""
H_H = """\
static inline int hin(int x) { return x; }
static inline int hdead(int x) { return x - 1; }
"""
# Never compiled by the build (an alternative backend): the model does not see it.
T_C = "int template_only(int x) { return x; }\n"


def _fn(file: str, name: str, line: int, **kw: object) -> dict:
    rec = {
        "file": file,
        "name": name,
        "line": line,
        "end_line": line,
        "lines": 1,
        "static": False,
        "inline": False,
        "header": False,
        "loops": 0,
        "cyclomatic": 1,
        "source": "frama-c-kernel",
        "units": ["lib"],
    }
    rec.update(kw)
    return rec


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "alt").mkdir()
    (tmp_path / "src/a.c").write_text(A_C, encoding="utf-8")
    (tmp_path / "src/b.c").write_text(B_C, encoding="utf-8")
    (tmp_path / "include/h.h").write_text(H_H, encoding="utf-8")
    (tmp_path / "alt/t.c").write_text(T_C, encoding="utf-8")
    return tmp_path


def _model(fallback: bool = False) -> dict:
    fns = {
        "src/a.c#helper": _fn("src/a.c", "helper", 2, static=True),
        "src/a.c#cb": _fn("src/a.c", "cb", 3, static=True, address_taken=True),
        "src/a.c#api_run": _fn("src/a.c", "api_run", 4, loops=1, lines=6),
        "src/b.c#helper": _fn("src/b.c", "helper", 1, static=True),
        "src/b.c#api_other": _fn("src/b.c", "api_other", 2),
        "include/h.h#hin": _fn("include/h.h", "hin", 1, static=True, inline=True, header=True),
        "include/h.h#hdead": _fn("include/h.h", "hdead", 2, static=True, inline=True, header=True),
    }
    if fallback:
        # src/b.c is its own unit, libb, which Frama-C cannot parse.
        for fid in ("src/b.c#helper", "src/b.c#api_other"):
            fns[fid].update(source="gcc-callgraph-info", units=["libb"])
    edges = [
        {"caller": "src/a.c#api_run", "callee": "src/a.c#helper", "kind": "direct"},
        {"caller": "src/a.c#api_run", "callee": "src/a.c#cb", "kind": "indirect"},
        {"caller": "src/a.c#api_run", "callee": "include/h.h#hin", "kind": "direct"},
        {"caller": "src/b.c#api_other", "callee": "src/b.c#helper", "kind": "direct"},
    ]
    units = {"lib": {"kind": "library", "test": False, "files": ["src/a.c", "src/b.c"], "parse": {"status": "ok"}}}
    if fallback:
        units = {
            "lib": {"kind": "library", "test": False, "files": ["src/a.c"], "parse": {"status": "ok"}},
            "libb": {
                "kind": "library",
                "test": False,
                "files": ["src/b.c"],
                "parse": {"status": "gcc_fallback", "error": "b.c:1: syntax error"},
            },
        }
    return {
        "status": "ok",
        "generated_at": "2026-11-08T00:00:00Z",
        "functions": fns,
        "edges": edges,
        "units": units,
        "macro_aliases": {
            "run_api": {"function": "api_run", "ids": ["src/a.c#api_run"], "via": "define", "defined_in": "x.h"}
        },
        "entry_points": ["src/a.c#api_run", "src/b.c#api_other"],
        "thread_entries": [],
    }


def _dag(target: Path, model: dict) -> dict:
    return bcd.build_dag(target, model, units=False)


def test_functions_and_edges_come_from_the_model(target: Path) -> None:
    dag = _dag(target, _model())

    assert dag["callgraph_source"] == "frama_c"
    assert set(dag["functions"]) == {
        "src/a.c#helper",
        "src/b.c#helper",
        "cb",
        "api_run",
        "api_other",
        "hin",
        "hdead",
    }
    assert "template_only" not in dag["functions"]
    run = dag["functions"]["api_run"]
    assert run["internal_callees"] == ["cb", "hin", "src/a.c#helper"]
    assert run["callgraph_source"] == "frama_c"
    assert run["has_loops"] and run["loop_count"] == 1
    assert dag["functions"]["src/b.c#helper"]["internal_callers"] == ["api_other"]
    # The signature facts come from the model.
    assert "params" in run
    # The indirect edge orders the waves: cb is below api_run.
    assert dag["functions"]["cb"]["wave"] < run["wave"]
    assert {c["function"] for c in dag["name_collisions"]} == {"helper"}
    assert dag["macro_aliases"] == {"run_api": ["api_run"]}


def test_header_functions_are_reached_only_from_entry_points(target: Path) -> None:
    dag = _dag(target, _model())
    assert dag["functions"]["hin"]["header"] and dag["functions"]["hin"]["reached"]
    assert dag["functions"]["hdead"]["header"] and not dag["functions"]["hdead"]["reached"]
    assert "reached" not in dag["functions"]["api_run"]


def test_an_executables_embedded_api_reaches_header_functions(target: Path) -> None:
    # hdead is reached only from api_other, which is embedded API of an executable (a library
    # compiled straight into it), not an export: it is API all the same, so hdead is reached.
    model = _model()
    model["edges"].append({"caller": "src/b.c#api_other", "callee": "include/h.h#hdead", "kind": "direct"})
    model["entry_points"] = ["src/a.c#api_run"]
    model["units"]["tool"] = {"kind": "executable", "test": False, "files": [], "embedded_api": ["src/b.c#api_other"]}
    assert bcd.model_api(model) == ["src/a.c#api_run", "src/b.c#api_other"]
    dag = _dag(target, model)
    assert dag["functions"]["hdead"]["reached"]
    # A test unit's embedded API is not the build's API.
    model["units"]["tool"]["test"] = True
    assert not _dag(target, model)["functions"]["hdead"]["reached"]


def test_modules_are_held_and_recounted(target: Path) -> None:
    dag = _dag(target, _model())
    # Header functions join the module of the files compiling them.
    assert set(dag["modules"]) == {"a", "b"}
    for mod in dag["modules"].values():
        assert mod["function_count"] == len(mod["functions"])
        assert mod["tier"]
    every = [k for m in dag["modules"].values() for k in m["functions"]]
    assert sorted(every) == sorted(dag["functions"])
    for mod in dag["modules"].values():
        assert set(mod["candidate_entry_points"]) <= set(mod["functions"])


def test_fallback_units_are_flagged(target: Path) -> None:
    dag = _dag(target, _model(fallback=True))
    assert dag["model"]["gcc_fallback_units"] == ["libb"]
    assert dag["functions"]["api_other"]["callgraph_source"] == "gcc_callgraph"
    assert dag["functions"]["api_other"]["callgraph_fallback"] == "b.c:1: syntax error"
    assert "b.c:1: syntax error" in dag["functions"]["api_other"]["eva_wp_blocked"]
    assert "eva_wp_blocked" not in dag["functions"]["api_run"]
    assert any("GCC" in w for w in dag["warnings"])


def test_fallback_link_units_are_fuzzed_with_sanitizers_and_blocked_for_eva_and_wp(target: Path) -> None:
    """The plan's decision for a unit Frama-C cannot parse (defect 6)."""
    dag = bcd.build_dag(target, _model(fallback=True))
    assert dag["module_kind"] == "link_unit"
    libb = dag["modules"]["libb"]
    assert libb["callgraph_fallback"] == "b.c:1: syntax error"
    assert libb["run_eva"] is False and libb["run_wp_full"] is False and libb["fuzz_engine"] == "sanitizers"
    assert dag["modules"]["lib"]["run_eva"] is True and "fuzz_engine" not in dag["modules"]["lib"]
    # The harnesses of its path module run under the same flags.
    assert dag["unit_of_lexer_module"]["b"] == "libb"
    assert dag["lexer_modules"]["b"]["run_eva"] is False and dag["lexer_modules"]["b"]["fuzz_engine"] == "sanitizers"
    assert all("eva_wp_blocked" in dag["functions"][k] for k in libb["functions"])
    assert not any("eva_wp_blocked" in dag["functions"][k] for k in dag["modules"]["lib"]["functions"])
    assert any("libb" in w and "sanitizers" in w for w in dag["warnings"])


def test_link_options_name_the_build_libraries() -> None:
    assert bcd.link_option("-lm") == "-lm"
    assert bcd.link_option("/usr/lib/x86_64-linux-gnu/libz.so") == "-lz"
    assert bcd.link_option("/opt/vendor/lib/libbar.a") == "-lbar"
    # A versioned file, or one without the lib prefix: the file itself.
    assert bcd.link_option("/usr/lib/libfoo.so.1") == "-l:libfoo.so.1"
    assert bcd.link_option("/opt/x/plugin.so") == "-l:plugin.so"


def _capture(**compile_fields: dict) -> dict:
    """libpng's shape: a static archive (no link line) and a shared library built from the same files."""
    return {
        "units": {
            "lib": {"kind": "static_lib", "test": False, "files": ["src/a.c", "src/b.c"], "objects": ["a.o", "b.o"]},
            "lib.so": {
                "kind": "shared_lib",
                "test": False,
                "files": ["src/a.c", "src/b.c"],
                "objects": ["a.pic.o", "b.pic.o"],
                "external_libs": [{"ref": "/usr/lib/x86_64-linux-gnu/libz.so", "libdirs": []}, {"ref": "-lm"}],
            },
            "tool": {
                "kind": "executable",
                "test": False,
                "files": ["tool.c"],
                "objects": ["tool.o"],
                "links": ["lib.so"],
                "external_libs": [{"ref": "-lpthread"}, {"ref": "-lm"}],
            },
            "unit_test": {"kind": "executable", "test": True, "files": ["t.c"], "objects": ["t.o"], "links": ["lib"]},
        },
        "compiles": [
            {"source": src, "object": obj, **compile_fields.get(src, {})}
            for src, obj in (("src/a.c", "a.o"), ("src/b.c", "b.o"), ("t.c", "t.o"))
        ],
    }


def test_a_static_library_takes_the_link_libraries_of_its_shared_sibling() -> None:
    options = bcd.unit_link_options(_capture())
    assert options["lib"] == ["-lz", "-lm"]
    assert options["lib.so"] == ["-lz", "-lm"]
    # Its own, then those of the project library it links; a library named twice keeps its last place.
    assert options["tool"] == ["-lpthread", "-lz", "-lm"]
    # No sibling compiles its sources: the units linking it give theirs.
    cap = _capture()
    cap["units"]["lib"]["files"] = ["src/only_static.c"]
    cap["units"]["tool"]["links"] = ["lib"]
    assert bcd.unit_link_options(cap)["lib"] == ["-lpthread", "-lm"]
    assert bcd.unit_link_options(None) == {}


def test_link_unit_modules_carry_their_link_libraries(target: Path) -> None:
    dag = bcd.build_dag(target, _model(), _capture())
    assert dag["modules"]["lib"]["ldflags"] == ["-lz", "-lm"]
    assert "fuzz_engine" not in dag["modules"]["lib"]


def test_a_unit_calling_setjmp_is_fuzzed_with_the_sanitizers(target: Path) -> None:
    model = _model(fallback=True)
    model["functions"]["src/a.c#api_run"]["external_calls"] = ["longjmp"]
    model["functions"]["src/a.c#helper"]["external_calls"] = ["_setjmp"]
    model["externals"] = ["_setjmp", "longjmp"]
    dag = bcd.build_dag(target, model)
    lib = dag["modules"]["lib"]
    assert lib["fuzz_engine"] == "sanitizers"
    assert "calls setjmp/longjmp (api_run, helper)" in lib["fuzz_engine_reason"]
    # Its path module's record, which its harnesses run under, follows; Eva and WP still run.
    assert dag["lexer_modules"]["a"]["fuzz_engine"] == "sanitizers"
    assert lib.get("run_eva", True) is not False
    # The GCC-fallback unit keeps its own reason.
    assert dag["modules"]["libb"]["fuzz_engine_reason"] == bcd.FALLBACK_ENGINE_REASON
    assert any("module lib: calls setjmp/longjmp" in w for w in dag["warnings"])


def test_a_unit_including_setjmp_h_is_fuzzed_with_the_sanitizers(target: Path) -> None:
    # E-ACSL stops on glibc's setjmp declaration even when nothing calls it (pngstest including png.h).
    dag = bcd.build_dag(target, _model(), _capture(**{"src/b.c": {"includes_setjmp_h": True}}))
    lib = dag["modules"]["lib"]
    assert lib["fuzz_engine"] == "sanitizers"
    assert lib["fuzz_engine_reason"].startswith("includes setjmp.h (src/b.c)")
    assert "fuzz_engine" not in bcd.build_dag(target, _model(), _capture())["modules"]["lib"]


def test_functions_only_the_build_defines_are_listed_and_warned(target: Path) -> None:
    built = {
        "src/a.c": {
            "defined_functions": [
                "src/a.c#api_run",
                "src/a.c#helper",
                "src/a.c#helper.part.0",  # a compiler clone
                "src/a.c#hin",  # a header inline without debug info: placed in its includer
                "src/a.c#simd_filter",
            ]
        },
        "src/b.c": {"defined_functions": ["src/b.c#api_other", "src/b.c#simd_init"]},
        # A test unit's file: the model never parses it.
        "t.c": {"defined_functions": ["t.c#main"]},
    }
    assert bcd.build_only_functions(_model(), _capture(**built)) == {
        "src/a.c": ["simd_filter"],
        "src/b.c": ["simd_init"],
    }
    dag = bcd.build_dag(target, _model(), _capture(**built))
    assert dag["build_only_functions"] == {"src/a.c": ["simd_filter"], "src/b.c": ["simd_init"]}
    assert any(
        w.startswith("src/b.c: the build defines 1 function(s) Frama-C's parse lacks (simd_init)")
        for w in dag["warnings"]
    )
    # A capture from before the comparison has no `defined_functions`: nothing to report.
    assert "build_only_functions" not in bcd.build_dag(target, _model(), _capture())


BLOCKERS_C = """\
int retry(int n) {
again:
    if (n-- > 0) goto again;
    return n;
}
int cleanup(int n) {
    if (n < 0) goto out;   /* a forward goto: not a blocker */
    n++;
out:
    return n; // goto out; volatile asm in a comment
}
struct item { int key; struct node link; };
struct item *owner(struct node *p) {
    return container_of(p, struct item, link);
}
void zero(unsigned char *p, int n) {
    volatile unsigned char *q = p;
    while (n--) *q++ = 0;
}
void fence(void) {
    __asm__ __volatile__("" ::: "memory");
}
int quoted(void) {
    const char *s = "goto volatile container_of";
    return s[0];
}
"""


def test_source_wp_blockers_come_back(tmp_path: Path) -> None:
    """Backward gotos, container_of, volatile and asm make a function a WP shell (defect 2)."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src/k.c").write_text(BLOCKERS_C, encoding="utf-8")
    spans = {"retry": (1, 5), "cleanup": (6, 11), "owner": (13, 15), "zero": (16, 19), "fence": (20, 22)}
    spans["quoted"] = (23, 26)
    fns = {f"src/k.c#{n}": _fn("src/k.c", n, a, end_line=b, units=["lib"]) for n, (a, b) in spans.items()}
    model = {
        "status": "ok",
        "functions": fns,
        "edges": [],
        "units": {"lib": {"kind": "library", "test": False, "files": ["src/k.c"], "parse": {"status": "ok"}}},
        "entry_points": [],
    }
    fn = bcd.build_dag(tmp_path, model, units=False)["functions"]
    assert fn["retry"]["wp_blockers"] == ["irreducible_goto"]
    assert fn["owner"]["wp_blockers"] == ["container_of"]
    assert fn["zero"]["wp_blockers"] == ["volatile_or_asm"]
    assert fn["fence"]["wp_blockers"] == ["volatile_or_asm"]
    for name in ("retry", "owner", "zero", "fence"):
        assert fn[name]["verifiability"] == "shell_unverifiable_wp", name
    for name in ("cleanup", "quoted"):
        assert fn[name]["wp_blockers"] == [] and fn[name]["verifiability"] == "core_provable", name
    # Without the sources (a file the work tree lacks), no source blocker is guessed.
    (tmp_path / "src/k.c").unlink()
    assert bcd.build_dag(tmp_path, model, units=False)["functions"]["retry"]["wp_blockers"] == []


def test_load_model_refuses_a_failed_model(tmp_path: Path) -> None:
    missing, why = bcd.load_model(tmp_path / "none.json")
    assert missing is None and "not found" in str(why)
    bad = tmp_path / "m.json"
    bad.write_text(json.dumps({"status": "failed"}), encoding="utf-8")
    assert bcd.load_model(bad)[0] is None
    bad.write_text(json.dumps(_model()), encoding="utf-8")
    assert bcd.load_model(bad)[0] is not None


def test_seed_uses_the_model_view(target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import ledger

    dag = _dag(target, _model(fallback=True))
    dag_path = tmp_path / "dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    run = tmp_path / "run"
    (run / "workspace/reports").mkdir(parents=True)
    monkeypatch.chdir(run)
    out = ledger.cmd_seed(dag_path, [], "frama_c")
    units, _ = ledger.load_state()
    fns = {(u["file"], u["function"]) for u in units.values()}
    assert ("include/h.h", "hin") in fns
    by_fn = {(u["file"], u["function"], u["obligation_class"]): u for u in units.values()}
    dead = by_fn[("include/h.h", "hdead", "rte")]
    assert dead["status"] == "deferred" and dead["unresolved"] == [ledger.HEADER_UNREACHED]
    assert by_fn[("include/h.h", "hin", "rte")]["status"] == "planned"
    assert out["deferred_unreached_header_units"] == 1
    assert ("src/a.c", "helper") in fns and ("src/b.c", "helper") in fns
    assert by_fn[("src/a.c", "api_run", "rte")]["callgraph_source"] == "frama_c"
    assert by_fn[("src/a.c", "api_run", "rte")]["status"] == "planned"
    other = by_fn[("src/b.c", "api_other", "rte")]
    assert other["callgraph_source"] == "gcc_callgraph"
    assert other["bookkeeping"]["callgraph_fallback"] == "b.c:1: syntax error"
    # Eva and WP cannot run on a unit Frama-C cannot parse: its units wait, with the reason (defect 6).
    assert other["status"] == "deferred" and other["unresolved"][0].startswith(f"{ledger.CALLGRAPH_FALLBACK}: ")
    assert out["deferred_callgraph_fallback_units"] == 2


def test_harness_reach_follows_keys_and_aliases(target: Path) -> None:
    dag = _dag(target, _model())
    module = dag["functions"]["api_run"]["module"]
    # The harness calls the API through the build's macro alias only.
    res = harness_reach.check_module(module, dag, {}, "int main(void){ return run_api(3); }", [])
    assert "api_run" in res["roots"]
    reached = harness_reach.callee_closure({"api_run"}, harness_reach._functions_by_name(dag), module)
    # The colliding static helper is named by its key in the edges and reached under it.
    assert {"src/a.c#helper", "cb", "hin"} <= reached
    assert "src/b.c#helper" not in reached
