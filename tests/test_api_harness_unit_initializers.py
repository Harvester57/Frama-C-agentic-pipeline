"""`--api` cases initialize a context struct with an initializer of the whole unit (mpack run-3, S8).

mpack's initializers (`mpack_writer_init`, `mpack_reader_init_data`, `mpack_tree_init_data`) sit in
other clusters of `libmpack_a` than most of the API that takes their objects. The generator looked
for an initializer only among the module's scope, so every case of `mpack_writer_2` passed an
all-zero `mpack_writer_t`, and a zero-length write reached `mpack_memcpy(NULL, p, 0)`: a Crash
Verifier rejected the crash as `harness_induced`.
"""

from __future__ import annotations

from typing import Any

import pytest

import api_harness as ah
import harness_reach as hr

pytestmark = pytest.mark.unit

# One link unit `lib` split in two clusters: the API under test, and the object's life cycle.
API_FNS = ["ctx_write", "ctx_size"]
LIFE_FNS = ["ctx_init", "ctx_init_error", "ctx_init_stdfile", "ctx_destroy"]

UNIT_INIT_MODEL: dict[str, Any] = {
    "status": "ok",
    "functions": {
        f"{'api.c' if n in API_FNS else 'life.c'}#{n}": {
            "name": n,
            "signature": sig,
            "formals": [{"name": a, "kind": k} for a, k in formals],
        }
        for n, sig, formals in [
            (
                "ctx_write",
                "void(struct ctx *,char *,unsigned long)",
                [("c", "pointer"), ("data", "const_pointer"), ("count", "value")],
            ),
            ("ctx_size", "unsigned long(struct ctx *)", [("c", "pointer")]),
            (
                "ctx_init",
                "void(struct ctx *,char *,unsigned long)",
                [("c", "pointer"), ("buf", "pointer"), ("size", "value")],
            ),
            ("ctx_init_error", "void(struct ctx *,int)", [("c", "pointer"), ("error", "value")]),
            (
                "ctx_init_stdfile",
                "void(struct ctx *,struct _IO_FILE *,int)",
                [("c", "pointer"), ("stream", "pointer"), ("close_when_done", "value")],
            ),
            ("ctx_destroy", "int(struct ctx *)", [("c", "pointer")]),
        ]
    },
}


def _split_dag() -> dict:
    functions = {
        n: {"name": n, "file": f, "is_static": False, "module": "lib", "internal_callees": []}
        for f, names in (("api.c", API_FNS), ("life.c", LIFE_FNS))
        for n in names
    }
    return {
        "module_kind": "link_unit",
        "modules": {
            "lib": {
                "candidate_entry_points": [*API_FNS, *LIFE_FNS],
                "functions": list(functions),
                "files": ["api.c", "life.c"],
            }
        },
        "submodules": {
            "lib__api": {"unit": "lib", "functions": list(API_FNS)},
            "lib__life": {"unit": "lib", "functions": list(LIFE_FNS)},
        },
        "functions": functions,
    }


def _plan(module: str = "lib__api", traces: list[list[dict]] | None = None) -> dict:
    return ah.plan(_split_dag(), UNIT_INIT_MODEL, module, "lib", 64, traces)


def _case_and_layout(p: dict, entry: str) -> tuple[str, dict]:
    # The single case: a stateful sequence case (`ctx_size` after `ctx_write`s) names the entry point too.
    (i,) = [k for k, lay in enumerate(p["layouts"]) if lay.get("entry") == entry and lay["kind"] == "single"]
    return p["cases"][i], p["layouts"][i]


def test_the_initializer_of_another_cluster_sets_up_the_context():
    p = _plan()
    stmt, lay = _case_and_layout(p, "ctx_size")
    init = stmt.index("(void)ctx_init((struct ctx *)&c0a0,")
    assert init < stmt.index("(void)ctx_size(&c0a0)") < stmt.index("(void)ctx_destroy(&c0a0)")
    assert [i["fn"] for i in lay["inits"]] == ["ctx_init"]


def test_error_and_stdfile_initializers_are_never_chosen():
    p = _plan()
    for entry in API_FNS:
        stmt, _ = _case_and_layout(p, entry)
        assert "ctx_init_error(" not in stmt and "ctx_init_stdfile(" not in stmt, stmt
    # Not even when the target's tests call one of them first.
    traced = _plan(traces=[[{"fn": "ctx_init_error"}, {"fn": "ctx_init_stdfile"}, {"fn": "ctx_init"}]])
    stmt, _ = _case_and_layout(traced, "ctx_write")
    assert "(void)ctx_init((struct ctx *)&c0a0," in stmt and "ctx_init_error(" not in stmt


def test_the_api_under_test_keeps_the_rest_of_the_input():
    # ctx_init's buffer is an output: a spare buffer, its size from the input. ctx_write's data is the
    # input's rest, as without the initializer; the initializer's slots come before the call's own.
    _, lay = _case_and_layout(_plan(), "ctx_write")
    assert lay["rest"] == {"call": 0, "param": 1, "kind": "bytes"}
    init_call = lay["inits"][0]["call"]
    calls = [s["call"] for s in lay["slots"]]
    assert init_call in calls
    assert calls.index(init_call) == 0


def test_the_out_of_scope_helpers_are_listed_for_the_reach_gate():
    assert _plan()["helpers"] == ["ctx_destroy", "ctx_init"]
    # In the life cycle cluster they are its own entry points: no helper to leave out.
    assert _plan("lib__life")["helpers"] == []


def test_an_input_backed_buffer_initializer_wins():
    recs = {
        "r_init": ("void(struct r *,char *,unsigned long,unsigned long)", ["pointer", "pointer", "value", "value"]),
        "r_init_data": ("void(struct r *,char *,unsigned long)", ["pointer", "const_pointer", "value"]),
        "r_init_growable": ("void(struct r *,char **,unsigned long *)", ["pointer", "pointer", "pointer"]),
        "r_init_error": ("void(struct r *,int)", ["pointer", "value"]),
    }
    names = {"r_init": ["r", "buf", "capacity", "count"], "r_init_data": ["r", "data", "count"]}
    functions = {
        n: {
            "name": n,
            "signature": sig,
            "formals": [{"name": (names.get(n) or ["r", "a", "b", "c"])[i], "kind": k} for i, k in enumerate(kinds)],
        }
        for n, (sig, kinds) in recs.items()
    }
    chosen, cands, _ = ah.initializers(functions)
    assert chosen["struct r"] == "r_init_data"
    assert cands["struct r"] == set(recs)
    # A trace does not beat an input-backed buffer, but breaks the tie among the others.
    del functions["r_init_data"]
    chosen, _, _ = ah.initializers(functions, [[{"fn": "r_init_growable"}, {"fn": "r_init"}]])
    assert chosen["struct r"] == "r_init"
    del functions["r_init"]
    chosen, _, _ = ah.initializers(functions, [[{"fn": "r_init_error"}]])
    assert chosen["struct r"] == "r_init_growable"
    del functions["r_init_growable"]
    chosen, cands, _ = ah.initializers(functions)
    # An error initializer alone sets up nothing worth fuzzing: no initializer, but its own case
    # still knows it is one.
    assert "struct r" not in chosen and cands["struct r"] == {"r_init_error"}


def _reach_dag() -> dict:
    """ctx_init (another cluster) calls a header inline `ctx_reset`, an entry point of the API cluster."""
    dag = _split_dag()
    fns = dag["functions"]
    fns["ctx_reset"] = {
        "name": "ctx_reset",
        "file": "api.h",
        "header": True,
        "is_static": True,
        "module": "lib",
        "internal_callees": [],
    }
    fns["ctx_init"]["internal_callees"] = ["ctx_reset"]
    fns["ctx_size"]["internal_callees"] = []
    dag["modules"]["lib"]["candidate_entry_points"].append("ctx_reset")
    dag["modules"]["lib"]["functions"].append("ctx_reset")
    dag["submodules"]["lib__api"]["functions"].append("ctx_reset")
    return dag


REACH_HARNESS = """
void case0(void) { struct ctx c0a0; ctx_init(&c0a0, buf, 8); (void)ctx_size(&c0a0); (void)ctx_destroy(&c0a0); }
void case1(void) { struct ctx c0a0; ctx_init(&c0a0, buf, 8); ctx_write(&c0a0, d, 1); (void)ctx_destroy(&c0a0); }
"""


@pytest.mark.parametrize("init_inline", [False, True])
def test_an_out_of_scope_helper_is_no_reach_root(init_inline):
    dag = _reach_dag()
    if init_inline:
        dag["functions"]["ctx_init"].update(header=True, is_static=True)
    mm = hr.ModuleMap(dag, {"lib__api": {"unit": "lib"}})
    sidecar = {"unit": "lib", "harness_file": "h.c", "api_helpers": ["ctx_destroy", "ctx_init"]}
    row = hr.check_module("lib__api", dag, sidecar, REACH_HARNESS, [], mm)
    assert "ctx_init" not in row["roots"] and "ctx_destroy" not in row["roots"]
    # ctx_reset runs only inside the initializer, with its fixed arguments: no case drives it.
    assert row["gaps"] == ["ctx_reset"]
    # Without the list (an older sidecar) the roots are the text's, as before.
    old = hr.check_module("lib__api", dag, {"unit": "lib", "harness_file": "h.c"}, REACH_HARNESS, [], mm)
    assert "ctx_init" in old["roots"]
    assert old["gaps"] == ([] if init_inline else ["ctx_reset"])


def test_c3_flow_cluster_rejects_oversized_cross_cluster_initializer_and_prefers_in_cluster():
    """B7 / D2: within-limit address_flow clusters reject huge cross-cluster inits, allow small ones, prefer in-cluster."""
    big_helpers = [f"big_h{i}" for i in range(6)]
    functions: dict[str, Any] = {
        "api_use": {
            "name": "api_use",
            "file": "api.c",
            "is_static": False,
            "module": "lib",
            "loc": 10,
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "small_init": {
            "name": "small_init",
            "file": "small.c",
            "is_static": False,
            "module": "lib",
            "loc": 10,
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "huge_init": {
            "name": "huge_init",
            "file": "huge.c",
            "is_static": False,
            "module": "lib",
            "loc": 10,
            "internal_callees": big_helpers,
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "local_init": {
            "name": "local_init",
            "file": "api.c",
            "is_static": False,
            "module": "lib",
            "loc": 10,
            "internal_callees": [],
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        "huge_destroy": {
            "name": "huge_destroy",
            "file": "huge.c",
            "is_static": False,
            "module": "lib",
            "loc": 10,
            "internal_callees": big_helpers,
            "indirect_callees": [],
            "address_refs": [],
            "global_refs": [],
        },
        **{
            h: {
                "name": h,
                "file": "huge.c",
                "is_static": True,
                "module": "lib",
                "loc": 10,
                "internal_callees": [],
                "indirect_callees": [],
                "address_refs": [],
                "global_refs": [],
            }
            for h in big_helpers
        },
    }
    model: dict[str, Any] = {
        "status": "ok",
        "functions": {
            "api.c#api_use": {
                "name": "api_use",
                "signature": "void(struct cycle *,struct small *)",
                "formals": [{"name": "c", "kind": "pointer"}, {"name": "s", "kind": "pointer"}],
            },
            "huge.c#huge_init": {
                "name": "huge_init",
                "signature": "void(struct cycle *)",
                "formals": [{"name": "c", "kind": "pointer"}],
            },
            "huge.c#huge_destroy": {
                "name": "huge_destroy",
                "signature": "void(struct cycle *)",
                "formals": [{"name": "c", "kind": "pointer"}],
            },
            "small.c#small_init": {
                "name": "small_init",
                "signature": "void(struct small *,char *,unsigned long)",
                "formals": [
                    {"name": "s", "kind": "pointer"},
                    {"name": "data", "kind": "const_pointer"},
                    {"name": "len", "kind": "value"},
                ],
            },
            "api.c#local_init": {
                "name": "local_init",
                "signature": "void(struct small *)",
                "formals": [{"name": "s", "kind": "pointer"}],
            },
        },
    }

    def _dag(with_local: bool = False, over_limit: bool = False) -> dict:
        sub: dict[str, Any] = {
            "unit": "lib",
            "reach": "address_flow",
            "anchors": ["api_use", *(["local_init"] if with_local else [])],
            "functions": ["api_use", *(["local_init"] if with_local else [])],
            "build_sources": ["api.c"],
        }
        if over_limit:
            sub["over_limit"] = "8 functions > 4"
        return {
            "module_kind": "link_unit",
            "unit_split": {"max_functions": 4, "max_lines": 1000},
            "global_variables": {},
            "modules": {
                "lib": {
                    "candidate_entry_points": ["api_use", "small_init", "huge_init", "local_init"],
                    "functions": sorted(functions),
                    "files": ["api.c", "small.c", "huge.c"],
                    "linked_modules": [],
                }
            },
            "submodules": {"lib__api": sub},
            "functions": functions,
        }

    # 1. Oversized huge_init (reach 8 > 4) is rejected with a case note; small_init (reach 2 <= 4) is chosen.
    p = ah.plan(_dag(with_local=False), model, "lib__api", "lib", 64)
    stmt, lay = _case_and_layout(p, "api_use")
    assert "huge_init(" not in stmt and "huge_destroy(" not in stmt
    assert "small_init(" in stmt
    assert any("initializer huge_init skipped: cross-cluster reach exceeds cluster limit" in n for n in lay["notes"])

    # 2. In-cluster local_init beats cross-cluster small_init even though small_init has an input-backed buffer pair.
    p_local = ah.plan(_dag(with_local=True), model, "lib__api", "lib", 64)
    stmt_local, _ = _case_and_layout(p_local, "api_use")
    assert "local_init(" in stmt_local and "small_init(" not in stmt_local

    # 3. Over-limit clusters keep existing behavior (huge_init is allowed).
    p_over = ah.plan(_dag(with_local=False, over_limit=True), model, "lib__api", "lib", 64)
    stmt_over, _ = _case_and_layout(p_over, "api_use")
    assert "huge_init(" in stmt_over
