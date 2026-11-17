"""`--api` cases never open input-named files, and release what an initializer set up (mpack run-3, S7).

`mpack_writer_init_filename(&writer, (char *)input)` fopen()ed a path the fuzzer chose on every
execution and nothing called `mpack_writer_destroy`: each run leaked a `FILE *`, and after ~64k runs
LibFuzzer stopped with `Too many open files` (RLIMIT_NOFILE 1024 in scripts/sandbox_exec.py).
"""

from __future__ import annotations

from typing import Any

import pytest

import api_harness as ah

pytestmark = pytest.mark.unit

PATHS_SPARE = ah.spare_bytes(64)


def _paths_dag(scope: list[str], unit_only: list[str]) -> dict:
    """A link unit `lib` whose API scope is `scope`; `unit_only` are its other (out of scope) functions."""
    functions = {n: {"name": n, "file": "lib.c", "is_static": False, "module": "lib"} for n in [*scope, *unit_only]}
    return {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": scope, "functions": list(functions)}},
        "functions": functions,
    }


def _paths_model(**recs: tuple[str, list[tuple[str, str]]]) -> dict:
    return {
        "status": "ok",
        "functions": {
            f"lib.c#{n}": {"name": n, "signature": sig, "formals": [{"name": a, "kind": k} for a, k in formals]}
            for n, (sig, formals) in recs.items()
        },
    }


WRITER_MODEL = _paths_model(
    w_init=("void(struct w *,char *,unsigned long)", [("w", "pointer"), ("buf", "pointer"), ("size", "value")]),
    w_init_filename=("void(struct w *,char *)", [("w", "pointer"), ("filename", "const_pointer")]),
    t_init_filename=(
        "void(struct t *,char *,unsigned long)",
        [("t", "pointer"), ("filename", "const_pointer"), ("max_bytes", "value")],
    ),
    w_size=("unsigned long(struct w *)", [("w", "pointer")]),
    w_destroy=("int(struct w *)", [("w", "pointer")]),
)
SCOPE = ["w_init", "w_init_filename", "t_init_filename", "w_size", "w_destroy"]


def _writer_plan(scope: list[str] = SCOPE, unit_only: list[str] | None = None) -> dict:
    dag = _paths_dag(scope, unit_only or [])
    return ah.plan(dag, WRITER_MODEL, "lib", "lib", 64)


def _case_of(p: dict, entry: str) -> str:
    (i,) = [k for k, lay in enumerate(p["layouts"]) if lay.get("entry") == entry]
    return p["cases"][i]


def test_a_function_taking_a_file_path_is_skipped_with_the_reason():
    p = _writer_plan()
    for fn in ("w_init_filename", "t_init_filename"):
        assert fn in p["skipped"], fn
        assert "file-system path" in p["skipped"][fn] and "filename" in p["skipped"][fn]
        assert not any(fn + "(" in c for c in p["cases"])


def test_an_initializers_own_case_releases_the_object():
    stmt = _case_of(_writer_plan(), "w_init")
    assert stmt.index("(void)w_init(") < stmt.index("(void)w_destroy(&c0a0);")


def test_a_context_object_is_released_after_the_call_under_test():
    p = _writer_plan()
    stmt = _case_of(p, "w_size")
    assert stmt.index("w_init(") < stmt.index("(void)w_size(") < stmt.index("(void)w_destroy(&c0a0);")
    lay = p["layouts"][[lay.get("entry") for lay in p["layouts"]].index("w_size")]
    # The release reads no input: the layout (and the seeds it drives) is the one without it.
    assert lay["inits"] == [{"fn": "w_init", "call": 1, "for": {"call": 0, "param": 0}}]
    assert {s["call"] for s in lay["slots"]} <= {0, 1}


def test_the_destructors_own_case_releases_once():
    stmt = _case_of(_writer_plan(), "w_destroy")
    assert stmt.count("w_destroy(") == 1


def test_the_destructor_may_come_from_outside_the_scope():
    # mpack: mpack_writer_destroy is in another cluster of the unit than mpack_writer_init.
    p = _writer_plan(["w_init", "w_size"], ["w_destroy"])
    assert "(void)w_destroy(&c0a0);" in _case_of(p, "w_size")


def test_an_initializer_that_takes_a_path_is_never_chosen_for_a_context_object():
    model = _paths_model(
        r_init_filename=("void(struct r *,char *)", [("r", "pointer"), ("filename", "const_pointer")]),
        r_read=("int(struct r *)", [("r", "pointer")]),
    )
    p = ah.plan(_paths_dag(["r_init_filename", "r_read"], []), model, "lib", "lib", 64)
    assert "r_init_filename" in p["skipped"]
    assert "r_init_filename" not in _case_of(p, "r_read")


def test_an_initializer_of_an_opaque_handle_is_released_once():
    # x_init's struct is a handle the headers only declare: the constructor builds it and the handle
    # release frees it; the struct release must not free it a second time.
    hx = "struct x *"
    recs = {
        "x_new": ("struct x *(void)", []),
        "x_init": ("int(struct x *)", [("x", "pointer")]),
        "x_free": ("void(struct x *)", [("x", "pointer")]),
    }
    model = _paths_model(**recs)
    protos: dict[str, dict[str, Any]] = {
        "x_new": {"ret": hx, "params": []},
        "x_init": {"ret": None, "params": [hx]},
        "x_free": {"ret": None, "params": [hx]},
    }
    visible = ah.Declared(set(recs), protos)
    p = ah.plan(_paths_dag(list(recs), []), model, "lib", "lib", 64, [], None, {}, visible)
    stmt = _case_of(p, "x_init")
    assert stmt.count("x_free(") == 1, stmt


@pytest.mark.parametrize(
    "name,hit",
    [
        ("filename", True),
        ("file_name", True),
        ("fname", True),
        ("path", True),
        ("pathname", True),
        ("filePath", True),
        ("dir_name", True),
        ("xpath", False),
        ("buf", False),
        ("profile", False),
    ],
)
def test_path_parameter_names(name, hit):
    rec = {"signature": "int(char *)", "formals": [{"name": name, "kind": "const_pointer"}]}
    assert (ah.path_parameter(rec) == name) is hit


def test_a_path_named_parameter_that_is_no_string_is_no_path():
    rec = {"signature": "int(int)", "formals": [{"name": "path", "kind": "value"}]}
    assert ah.path_parameter(rec) is None
    assert ah.single_case("f", rec, PATHS_SPARE)[0] is not None
