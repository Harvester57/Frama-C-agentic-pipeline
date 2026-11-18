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
