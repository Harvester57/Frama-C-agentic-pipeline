"""
H2 of docs/plans/templates-and-stubs-improvement-plan.md: synthesized call sequences on an opaque handle.
A handle type with a constructor and a destructor that no recorded chain covers gets one lifecycle
case: build the handle, call functions on it chosen by input bytes, release it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import generate_harness as gh
import seed_harvest as sh
import validate_artifacts as va

REPO = Path(__file__).resolve().parents[1]
SPARE = ah.spare_bytes(64)
CTX = "struct ctx *"


def _rec(name: str, signature: str, *kinds: str) -> dict:
    return {
        "name": name,
        "signature": signature,
        "formals": [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)],
    }


RECORDS = {
    "ctx_new": _rec("ctx_new", "struct ctx *(unsigned int)", "value"),
    "ctx_free": _rec("ctx_free", "void(struct ctx *)", "pointer"),
    "ctx_push": _rec("ctx_push", "int(struct ctx *,int)", "pointer", "value"),
    "ctx_reset": _rec("ctx_reset", "int(struct ctx *)", "pointer"),
    "ctx_sum": _rec("ctx_sum", "int(struct ctx *)", "pointer"),
    "ctx_merge": _rec("ctx_merge", "int(struct ctx *,struct ctx *)", "pointer", "pointer"),
}


def _api() -> ah.ApiInfo:
    handles = {n: {0: CTX} for n in RECORDS if n != "ctx_new"}
    handles["ctx_merge"] = {0: CTX, 1: CTX}
    return ah.ApiInfo(
        probed=True,
        records={"ctx_new": RECORDS["ctx_new"]},
        handles=handles,
        ctors={CTX: "ctx_new"},
        dtors={CTX: "ctx_free"},
        dtor_names={CTX: {"ctx_free"}},
        returns={"ctx_new": CTX},
    )


@pytest.mark.unit
def test_methods_take_the_handle_once_and_are_neither_its_constructor_nor_its_destructor():
    assert ah.lifecycle_methods(CTX, RECORDS, _api()) == ["ctx_push", "ctx_reset", "ctx_sum"]


@pytest.mark.unit
def test_lifecycle_case_builds_calls_by_input_byte_and_releases():
    api = _api()
    methods = ah.lifecycle_methods(CTX, RECORDS, api)
    stmt, layout, why = ah.lifecycle_case(CTX, methods, RECORDS, SPARE, api)
    assert stmt is not None and layout is not None, why
    assert f"{CTX} fc_h = ctx_new(c0a0);" in stmt
    assert f"for (unsigned int fc_i = 0; fc_i < {ah.LIFECYCLE_MAX_CALLS}U; fc_i++)" in stmt
    assert "if (fuzz_len < fuzz_off + 1) { break; }" in stmt
    assert "memcpy(&fc_op, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), 1);" in stmt
    assert "unsigned int fc_k = (unsigned int)fc_op % 3U;" in stmt
    # Each method gets the handle and its own arguments, read from the input where the loop is.
    assert "if (fc_k == 0U) {" in stmt and "(void)ctx_push((struct ctx *)fc_h, c1a1);" in stmt
    assert "else if (fc_k == 2U) { (void)ctx_sum((struct ctx *)fc_h); }" in stmt
    # Released once, after the loop, and only a constructed handle runs methods.
    assert stmt.count("ctx_free(") == 1 and stmt.endswith("(void)ctx_free(fc_h); } (void)fuzz_off;")
    assert "if (fc_h != 0) {" in stmt
    # No `case` label inside the case: seed_harvest.harness_cases reads them as dispatch cases.
    assert "case " not in stmt and "switch" not in stmt
    assert layout == {
        "kind": "lifecycle",
        "calls": ["ctx_new", "ctx_free"],
        "slots": [{"call": 0, "param": 0, "size": 4, "kind": "int"}],
        "rest": None,
        "handle": CTX,
        "methods": methods,
        "max_calls": ah.LIFECYCLE_MAX_CALLS,
    }


@pytest.mark.unit
def test_no_lifecycle_without_destructor_or_methods():
    api = _api()
    assert ah.lifecycle_case(CTX, [], RECORDS, SPARE, api)[2] == f"{CTX}: no other function takes the handle"
    api.dtors.clear()
    assert ah.lifecycle_case(CTX, ["ctx_sum"], RECORDS, SPARE, api)[0] is None


def _dag_and_model(names: list[str]) -> tuple[dict, dict]:
    functions = {f"lib.c#{n}": {"name": n, "file": "lib.c"} for n in names}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    model = {"status": "ok", "functions": {f"lib.c#{n}": RECORDS[n] for n in names}}
    return dag, model


def _declared() -> ah.Declared:
    params = {n: [CTX] for n in RECORDS if n != "ctx_new"}
    params["ctx_merge"] = [CTX, CTX]
    protos: dict[str, dict[str, Any]] = {n: {"ret": None, "params": p} for n, p in params.items()}
    protos["ctx_new"] = {"ret": CTX, "params": [None]}
    return ah.Declared(RECORDS, protos)


@pytest.mark.unit
def test_plan_adds_one_lifecycle_case_per_uncovered_handle_type():
    dag, model = _dag_and_model(list(RECORDS))
    p = ah.plan(dag, model, "lib", "lib", 64, [], None, {}, _declared())
    kinds = [lay["kind"] for lay in p["layouts"]]
    # ctx_merge takes two handles of a struct the header only declares: two zeroed `struct ctx`
    # objects would not compile, and who owns the handles after the merge is not known.
    assert kinds == ["single"] * (len(RECORDS) - 1) + ["lifecycle"]
    assert p["skipped"] == {
        "lib.c#ctx_merge": f"{CTX}: the call takes 2 such handles and who owns them afterwards is not known"
    }
    assert p["layouts"][-1]["methods"] == ["ctx_push", "ctx_reset", "ctx_sum"]
    # A recorded chain on the handle comes first but does not replace it: it passes the handle as a
    # zeroed buffer, never the constructor's result.
    p = ah.plan(dag, model, "lib", "lib", 64, [TRACE], None, {}, _declared())
    assert [lay["kind"] for lay in p["layouts"]][-2:] == ["sequence", "lifecycle"]


TRACE = [
    {"fn": "ctx_push", "args": {}, "addrs": {"0": "0x10"}},
    {"fn": "ctx_sum", "args": {}, "addrs": {"0": "0x10"}},
]


@pytest.mark.unit
def test_lifecycle_cases_share_the_sequence_cap(monkeypatch):
    dag, model = _dag_and_model(list(RECORDS))
    monkeypatch.setattr(ah, "MAX_SEQUENCE_CASES", 1)
    p = ah.plan(dag, model, "lib", "lib", 64, [TRACE], None, {}, _declared())
    assert [lay["kind"] for lay in p["layouts"]][-1] == "sequence"
    monkeypatch.setattr(ah, "MAX_SEQUENCE_CASES", 0)
    p = ah.plan(dag, model, "lib", "lib", 64, [], None, {}, _declared())
    assert all(lay["kind"] == "single" for lay in p["layouts"])


@pytest.mark.unit
def test_lifecycle_layout_validates_and_seeds_from_the_constructor_calls():
    api = _api()
    stmt, layout, _ = ah.lifecycle_case(CTX, ["ctx_sum"], RECORDS, SPARE, api)
    assert stmt is not None and layout is not None
    layout["selector"] = 0
    side = {
        "module": "lib",
        "harness_file": "harness_lib.c",
        "sources": ["lib.c"],
        "cppflags": "",
        "entry_fn": "ctx_new",
        "entry_style": "dispatch",
        "dispatch_cases": [stmt],
        "api_harness": True,
        "api_cases": [layout],
    }
    assert list(va.validate_sidecar(side, "lib")) == []
    calls = [{"fn": "ctx_new", "args": {"0": [["i", 0, "07000000"]]}}]
    assert sh.layout_seeds([layout], calls, [])[0] == [b"\x00\x07\x00\x00\x00"]


MODBUS = "struct _modbus *"


@pytest.mark.unit
def test_a_lib_new_kind_constructor_builds_the_handle():
    """libmodbus run-1: `modbus_new_tcp` / `modbus_new_rtu` (`<lib>_new_<kind>`) build `modbus_t`."""
    recs = {
        "modbus_new_tcp": _rec("modbus_new_tcp", "struct _modbus *(char const *,int)", "const_pointer", "value"),
        "modbus_new_rtu": _rec(
            "modbus_new_rtu",
            "struct _modbus *(char const *,int,char,int,int)",
            "const_pointer",
            "value",
            "value",
            "value",
            "value",
        ),
        "modbus_new_tcp_pi": _rec(
            "modbus_new_tcp_pi", "struct _modbus *(char const *,char const *)", "const_pointer", "const_pointer"
        ),
        "modbus_free": _rec("modbus_free", "void(struct _modbus *)", "pointer"),
        "modbus_flush": _rec("modbus_flush", "int(struct _modbus *)", "pointer"),
    }
    protos: dict[str, dict[str, Any]] = {
        "modbus_new_tcp": {"ret": MODBUS, "params": [None, None]},
        "modbus_new_rtu": {"ret": MODBUS, "params": [None, None, None, None, None]},
        "modbus_new_tcp_pi": {"ret": MODBUS, "params": [None, None]},
        "modbus_free": {"ret": None, "params": [MODBUS]},
        "modbus_flush": {"ret": None, "params": [MODBUS]},
    }
    declared = ah.Declared(set(recs), protos)
    handles, ctors, dtors, _, ctor_records, _ = ah.handle_functions(recs, declared)
    # All three are constructors; the fewest parameters win, then the name (tcp before tcp_pi).
    assert ctors == {MODBUS: "modbus_new_tcp"} and dtors == {MODBUS: "modbus_free"}
    assert set(ctor_records) == {"modbus_new_tcp"} and handles["modbus_flush"] == {0: MODBUS}
    for name in ("modbus_new_tcp", "modbus_new_rtu", "foo_create_bar", "new_foo", "foo_new", "ctx_init"):
        assert ah._INIT_NAME_RE.search(name), name
    for name in ("modbus_renew", "newline_count", "foo_news", "recreate_x"):
        assert not ah._INIT_NAME_RE.search(name), name
    # The plan builds the handle with the constructor (a string argument) instead of skipping its users.
    functions = {f"modbus.c#{n}": {"name": n, "file": "modbus.c"} for n in recs}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    model = {"status": "ok", "functions": {f"modbus.c#{n}": r for n, r in recs.items()}}
    p = ah.plan(dag, model, "lib", "lib", 64, [], None, {}, declared)
    assert p["skipped"] == {}
    flush = next(t for t, lay in zip(p["cases"], p["layouts"], strict=True) if lay.get("entry") == "modbus.c#modbus_flush")
    assert "modbus_new_tcp(" in flush and "modbus_flush(" in flush and "modbus_free(" in flush


def _modbus_plan(recs: dict[str, dict], protos: dict[str, dict[str, Any]], layouts: dict | None = None) -> dict:
    functions = {f"modbus.c#{n}": {"name": n, "file": "modbus.c"} for n in recs}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    model = {"status": "ok", "functions": {f"modbus.c#{n}": r for n, r in recs.items()}}
    return ah.plan(dag, model, "lib", "lib", 64, [], None, layouts or {}, ah.Declared(set(recs), protos))


def _entry_case(p: dict, name: str) -> str:
    return next(t for t, lay in zip(p["cases"], p["layouts"], strict=True) if lay.get("entry") == f"modbus.c#{name}")


@pytest.mark.unit
def test_the_destructor_that_frees_wins_over_close_and_close_runs_first():
    """
    libmodbus run-1: `modbus_close(modbus_t *)` only closes the socket, `modbus_free(modbus_t *)`
    frees the context. The first name (`modbus_close`) was the destructor, so `modbus_free` never ran
    and every execution leaked the context (LeakSanitizer: direct leaks in `modbus_new_tcp`). The
    destructor that releases memory wins; a `close` of the same handle runs before it, as libmodbus's
    own tests do (`modbus_close(ctx); modbus_free(ctx);`).
    """
    recs = {
        "modbus_new_tcp": _rec("modbus_new_tcp", "struct _modbus *(char const *,int)", "const_pointer", "value"),
        "modbus_close": _rec("modbus_close", "void(struct _modbus *)", "pointer"),
        "modbus_free": _rec("modbus_free", "void(struct _modbus *)", "pointer"),
        "modbus_flush": _rec("modbus_flush", "int(struct _modbus *)", "pointer"),
    }
    protos: dict[str, dict[str, Any]] = {
        "modbus_new_tcp": {"ret": MODBUS, "params": [None, None]},
        "modbus_close": {"ret": None, "params": [MODBUS]},
        "modbus_free": {"ret": None, "params": [MODBUS]},
        "modbus_flush": {"ret": None, "params": [MODBUS]},
    }
    _, _, dtors, dtor_names, _, _ = ah.handle_functions(recs, ah.Declared(set(recs), protos))
    assert dtors == {MODBUS: "modbus_free"} and dtor_names == {MODBUS: {"modbus_close", "modbus_free"}}
    p = _modbus_plan(recs, protos)
    both = "if (c0a0 != 0) { (void)modbus_close(c0a0); (void)modbus_free(c0a0); }"
    assert both in _entry_case(p, "modbus_flush")
    # The closer's own case: the context is still freed afterwards, and not closed twice.
    close = _entry_case(p, "modbus_close")
    assert "if (c0a0 != 0) { (void)modbus_free(c0a0); }" in close and close.count("modbus_close(") == 1, close
    # The destructor's own case releases nothing after it (no double free).
    free = _entry_case(p, "modbus_free")
    assert free.count("modbus_free(") == 1 and "modbus_close(" not in free, free
    life = next(lay for lay in p["layouts"] if lay["kind"] == "lifecycle")
    stmt = p["cases"][p["layouts"].index(life)]
    assert life["calls"] == ["modbus_new_tcp", "modbus_free"]
    # Neither is a method: a free inside the loop would be a use after free the harness makes.
    assert life["methods"] == ["modbus_flush"]
    assert stmt.endswith("(void)modbus_close(fc_h); (void)modbus_free(fc_h); } (void)fuzz_off;"), stmt
    for name in ("modbus_free", "ctx_destroy", "foo_release", "x_unref", "FooFree", "ctx_delete"):
        assert ah._FREEING_DTOR_RE.search(name), name
    for name in ("modbus_close", "ctx_cleanup", "ctx_deinit", "ctx_fini"):
        assert not ah._FREEING_DTOR_RE.search(name), name


@pytest.mark.unit
def test_a_close_that_frees_the_handle_is_no_closer():
    """
    A `close` that reaches `free` through its direct call sites frees the handle itself (sqlite3_close
    style): running the freeing destructor after it would be a double free the harness makes.
    """
    dtors = {CTX: "ctx_free"}
    names = {CTX: {"ctx_close", "ctx_free"}}
    model = {"lib.c#ctx_close": {"name": "ctx_close", "call_sites": [{"callee": "ctx_release_all"}]}}
    model["lib.c#ctx_release_all"] = {"name": "ctx_release_all", "external_calls": ["free"]}
    assert ah.handle_closers(dtors, names, model) == {}
    model.pop("lib.c#ctx_release_all")
    assert ah.handle_closers(dtors, names, model) == {CTX: "ctx_close"}
    # Only a destructor named for freeing gets a closer; a lone `close` destructor is the release itself.
    assert ah.handle_closers({CTX: "ctx_close"}, names, model) == {}
    assert ah.handle_closers(dtors, {CTX: {"ctx_cleanup", "ctx_free"}}, model) == {}


MAPPING = "struct _modbus_mapping_t"
MAPPING_LAYOUT = {"what": "struct", "size": 64, "align": 8, "pointers": True, "fields": []}


@pytest.mark.unit
def test_a_struct_made_by_a_constructor_is_released_by_its_freeing_destructor():
    """
    libmodbus run-1: `modbus_mapping_t *modbus_mapping_new_start_address(...)` returns a malloc'ed
    complete struct (no handle), and its case dropped the result: a leak per execution. The result is
    released with the struct's freeing destructor (`modbus_mapping_free`). That destructor's own case
    passed a zeroed stack object to `free` (ASan: attempting free on address which was not
    malloc()-ed): a struct with no initializer and a destructor that frees gets no such case, the
    constructor's case calls it.
    """
    ints = ",".join(["unsigned int"] * 8)
    recs = {
        "modbus_mapping_new_start_address": {
            **_rec("modbus_mapping_new_start_address", f"{MAPPING} *({ints})", *["value"] * 8),
            "call_sites": [{"callee": "malloc", "line": 1}],
        },
        "modbus_mapping_free": _rec("modbus_mapping_free", f"void({MAPPING} *)", "pointer"),
        "modbus_mapping_peek": _rec("modbus_mapping_peek", f"int({MAPPING} *)", "pointer"),
    }
    protos: dict[str, dict[str, Any]] = {n: {"ret": None, "params": [None] * 8} for n in recs}
    p = _modbus_plan(recs, protos, {MAPPING: MAPPING_LAYOUT})
    make = _entry_case(p, "modbus_mapping_new_start_address")
    assert f"{{ {MAPPING} * c0r = modbus_mapping_new_start_address(" in make, make
    assert "if (c0r != 0) { (void)modbus_mapping_free(c0r); } }" in make, make
    assert p["skipped"].get("modbus.c#modbus_mapping_free", "").startswith("frees its argument"), p["skipped"]
    # Not allocating (no allocator reached): the result is not known to be the caller's, left alone.
    recs["modbus_mapping_new_start_address"].pop("call_sites")
    make = _entry_case(_modbus_plan(recs, protos, {MAPPING: MAPPING_LAYOUT}), "modbus_mapping_new_start_address")
    assert "modbus_mapping_free(" not in make, make


def _lifecycle_sidecar(stmt: str, layout: dict, entry_fn: str) -> dict:
    layout["selector"] = 0
    return {
        "module": "lib",
        "harness_file": "harness_lib.c",
        "sources": ["lib.c"],
        "cppflags": "",
        "entry_fn": entry_fn,
        "entry_style": "dispatch",
        "dispatch_cases": [stmt],
        "api_harness": True,
        "api_cases": [layout],
    }


@pytest.mark.unit
def test_a_lifecycle_constructor_string_is_a_bounded_slot_never_the_rest():
    """
    libmodbus run-1: `modbus_new_tcp(const char *ip, int port)` as a lifecycle constructor bound its
    unsized string to the rest of the input (`rest: {kind: string}`), which the schema forbids (the
    method loop reads its op bytes after the constructor): `$.api_cases[67].rest: expected type null`.
    The string is a bounded input slot, NUL-terminated, and the rest stays null.
    """
    recs = {
        "modbus_new_tcp": _rec("modbus_new_tcp", "struct _modbus *(char const *,int)", "const_pointer", "value"),
        "modbus_free": _rec("modbus_free", "void(struct _modbus *)", "pointer"),
        "modbus_flush": _rec("modbus_flush", "int(struct _modbus *)", "pointer"),
    }
    api = ah.ApiInfo(
        probed=True,
        records={"modbus_new_tcp": recs["modbus_new_tcp"]},
        handles={"modbus_free": {0: MODBUS}, "modbus_flush": {0: MODBUS}},
        ctors={MODBUS: "modbus_new_tcp"},
        dtors={MODBUS: "modbus_free"},
        dtor_names={MODBUS: {"modbus_free"}},
        returns={"modbus_new_tcp": MODBUS},
    )
    stmt, layout, why = ah.lifecycle_case(MODBUS, ["modbus_flush"], recs, SPARE, api)
    assert stmt is not None and layout is not None, why
    n = ah.STRING_SLOT_BYTES
    assert layout["rest"] is None
    assert layout["slots"] == [
        {"call": 0, "param": 0, "size": n, "kind": "bytes"},
        {"call": 0, "param": 1, "size": 4, "kind": "int"},
    ]
    # A stack buffer of the slot's size, read from the input (fuzz_off advances), its last byte 0.
    assert f"unsigned char c0a0[{n}]; memset(c0a0, 0, sizeof(c0a0));" in stmt
    assert "memcpy(c0a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), sizeof(c0a0)); fuzz_off += sizeof(c0a0);" in stmt
    assert "c0a0[sizeof(c0a0) - 1] = 0;" in stmt
    assert "rest_n" not in stmt and "static _Alignas" not in stmt.split("fc_h =")[0]
    assert f"{MODBUS} fc_h = modbus_new_tcp((char const *)c0a0, c0a1);" in stmt
    assert any("NUL-terminated" in note for note in layout.get("notes") or [])
    assert list(va.validate_sidecar(_lifecycle_sidecar(stmt, layout, "modbus_new_tcp"), "lib")) == []
    # A recorded string seeds the slot (padded to its size), then the port.
    calls = [{"fn": "modbus_new_tcp", "args": {"0": [["s", 0, b"127.0.0.1".hex()]], "1": [["i", 0, "f6010000"]]}}]
    seed = b"\x00" + b"127.0.0.1".ljust(n, b"\0") + b"\xf6\x01\x00\x00"
    assert sh.layout_seeds([layout], calls, [])[0] == [seed]


@pytest.mark.unit
def test_an_out_parameter_lifecycle_constructor_string_is_a_bounded_slot_never_the_rest():
    """The out-parameter form (`int ctx_open(struct ctx **out, const char *path)`) gets the same slot."""
    recs = {
        "ctx_open": _rec("ctx_open", "int(struct ctx **,char const *)", "pointer", "const_pointer"),
        "ctx_free": RECORDS["ctx_free"],
        "ctx_sum": RECORDS["ctx_sum"],
    }
    api = ah.ApiInfo(
        probed=True,
        records={"ctx_open": recs["ctx_open"]},
        handles={"ctx_free": {0: CTX}, "ctx_sum": {0: CTX}},
        dtors={CTX: "ctx_free"},
        dtor_names={CTX: {"ctx_free"}},
        out_ctors={CTX: ("ctx_open", 0)},
    )
    stmt, layout, why = ah.lifecycle_case(CTX, ["ctx_sum"], recs, SPARE, api)
    assert stmt is not None and layout is not None, why
    assert layout["rest"] is None
    assert layout["slots"] == [{"call": 0, "param": 1, "size": ah.STRING_SLOT_BYTES, "kind": "bytes"}]
    assert "c0a1[sizeof(c0a1) - 1] = 0;" in stmt and "ctx_open((struct ctx **)&fc_h, (char const *)c0a1);" in stmt
    assert list(va.validate_sidecar(_lifecycle_sidecar(stmt, layout, "ctx_open"), "lib")) == []


@pytest.mark.unit
def test_an_out_parameter_constructor_string_in_a_single_case_is_a_slot_and_the_call_keeps_the_rest():
    """`_construct` reserves the rest for the call under test: its constructor's string is the bounded slot."""
    recs = {
        "ctx_open": _rec("ctx_open", "int(struct ctx **,char const *)", "pointer", "const_pointer"),
        "ctx_feed": _rec("ctx_feed", "int(struct ctx *,char const *)", "pointer", "const_pointer"),
    }
    api = ah.ApiInfo(
        probed=True,
        records={"ctx_open": recs["ctx_open"]},
        handles={"ctx_feed": {0: CTX}},
        dtors={CTX: "ctx_free"},
        dtor_names={CTX: {"ctx_free"}},
        out_ctors={CTX: ("ctx_open", 0)},
    )
    case = ah._Case(SPARE, api)
    params, _ = ah.plan_params(recs["ctx_feed"]["signature"], recs["ctx_feed"]["formals"])
    stmt = ah._bind_call(case, 0, "ctx_feed", params or [], recs["ctx_feed"]["formals"], recs["ctx_feed"])
    assert case.slots == [{"call": 1, "param": 1, "size": ah.STRING_SLOT_BYTES, "kind": "bytes"}]
    assert case.rest == {"call": 0, "param": 1, "kind": "string"}
    assert "c1a1[sizeof(c1a1) - 1] = 0;" in case.post
    assert "ctx_open((struct ctx **)&c0a0, (char const *)c1a1);" in " ".join([*case.decls, stmt])


@pytest.mark.unit
def test_a_lifecycle_constructor_byte_pair_never_takes_the_rest():
    """An unsized (buffer, length) input pair of the constructor: a spare buffer and a clamped length slot."""
    recs = {
        "ctx_from": _rec("ctx_from", "struct ctx *(unsigned char const *,size_t)", "const_pointer", "value"),
        "ctx_free": RECORDS["ctx_free"],
        "ctx_sum": RECORDS["ctx_sum"],
    }
    api = ah.ApiInfo(
        probed=True,
        records={"ctx_from": recs["ctx_from"]},
        handles={"ctx_free": {0: CTX}, "ctx_sum": {0: CTX}},
        ctors={CTX: "ctx_from"},
        dtors={CTX: "ctx_free"},
        dtor_names={CTX: {"ctx_free"}},
        returns={"ctx_from": CTX},
    )
    stmt, layout, why = ah.lifecycle_case(CTX, ["ctx_sum"], recs, SPARE, api)
    assert stmt is not None and layout is not None, why
    assert layout["rest"] is None
    assert layout["slots"] == [{"call": 0, "param": 1, "size": 8, "kind": "int"}]
    assert "fuzz_len - fuzz_off)" not in stmt.split("fc_h =")[1].split(";")[0]
    assert list(va.validate_sidecar(_lifecycle_sidecar(stmt, layout, "ctx_from"), "lib")) == []


# --- end to end: a use after free only a sequence of calls reaches ----------------------------------

LIB_H = """#include <stddef.h>
struct ctx;
struct ctx *ctx_new(unsigned int cap);
void ctx_free(struct ctx *c);
int ctx_push(struct ctx *c, int v);
int ctx_reset(struct ctx *c);
int ctx_sum(struct ctx *c);
"""

LIB_C = """#include <stdlib.h>
#include "lib.h"
struct ctx { int *buf; unsigned int cap; unsigned int n; int dead; };
struct ctx *ctx_new(unsigned int cap) {
    struct ctx *c = malloc(sizeof *c);
    if (c == NULL) return NULL;
    c->cap = cap % 8U + 1U;
    c->n = 0;
    c->dead = 0;
    c->buf = calloc(c->cap, sizeof *c->buf);
    if (c->buf == NULL) { free(c); return NULL; }
    return c;
}
void ctx_free(struct ctx *c) { if (c != NULL) { if (!c->dead) { free(c->buf); } free(c); } }
int ctx_push(struct ctx *c, int v) {
    if (c == NULL || c->buf == NULL || c->n >= c->cap) return -1;
    c->buf[c->n++] = v;
    return 0;
}
/* The bug: the buffer is freed, but only ctx_free knows; ctx_push and ctx_sum still use it. */
int ctx_reset(struct ctx *c) {
    if (c == NULL || c->dead) return -1;
    free(c->buf);
    c->dead = 1;
    c->n = 0;
    return 0;
}
int ctx_sum(struct ctx *c) {
    int s = 0;
    if (c == NULL || c->buf == NULL) return 0;
    for (unsigned int i = 0; i < c->cap; i++) s += c->buf[i];
    return s;
}
"""

LIFECYCLE_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsanitize=fuzzer,address -g -I. harness.c lib.c -o fz || exit 1
mkdir corpus
./fz -runs=500000 -seed=3 -max_len=64 corpus > fz.log 2>&1
grep -m1 -o "AddressSanitizer: [a-z-]*" fz.log
grep -m1 -E "#[0-9]+ .* in ctx_[a-z]+" fz.log
frama-c -eva -main eva_main -cpp-extra-args=-I. harness.c lib.c > eva.log 2>&1 && echo EVA_OK || tail -20 eva.log
"""


def _render(cases: list[str]) -> str:
    inv = gh._build_dispatch_invocation(cases)
    text = (REPO / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "lib",
        "MODULE_HEADER": "lib.h",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


@pytest.mark.integration
def test_lifecycle_case_reaches_a_use_after_free_no_single_case_reaches(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    names = ["ctx_new", "ctx_free", "ctx_push", "ctx_reset", "ctx_sum"]
    dag, model = _dag_and_model(names)
    p = ah.plan(dag, model, "lib", "lib", 64, [], None, {}, _declared())
    assert [lay["kind"] for lay in p["layouts"]][-1] == "lifecycle"
    (tmp_path / "lib.h").write_text(LIB_H, encoding="utf-8")
    (tmp_path / "lib.c").write_text(LIB_C, encoding="utf-8")
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE]
    results: dict[str, str] = {}
    for label, cases in (("single", p["cases"][:-1]), ("all", p["cases"])):
        (tmp_path / "harness.c").write_text(_render(cases), encoding="utf-8")
        proc = subprocess.run(
            [*argv, LIFECYCLE_SCRIPT], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900
        )
        results[label] = proc.stdout + proc.stderr
        assert "EVA_OK" in proc.stdout, results[label][-4000:]
    assert "heap-use-after-free" not in results["single"], results["single"][-4000:]
    assert "AddressSanitizer: heap-use-after-free" in results["all"], results["all"][-4000:]
    assert "in ctx_sum" in results["all"] or "in ctx_push" in results["all"], json.dumps(results["all"][-2000:])
