"""`--api` cases keep each argument inside the domain the API documents (mpack run-4).

Fuzzing the run-4 `--api` harnesses of MPack gave about a hundred crash artifacts, and every library
crash came from a case that broke a documented precondition: the Crash Verifier rejected each one as
`harness_induced`. The generator now normalizes an argument after reading it from the input, and only
when it is outside the documented domain, so a recorded seed keeps its meaning and no slot moves:

  A. a (min, max) pair of the same type (`mpack_expect_u8_range(reader, min_value, max_value)`) is
     ordered, and a NaN bound replaced (MPack asserts `min_value <= max_value`);
  B. the capacity of a writable NUL-terminated output (`mpack_node_copy_cstr(node, buffer, bufsize)`)
     and a `max_*` limit an initializer or a limit setter takes (`mpack_tree_init_stream`,
     `mpack_tree_set_limits`) are at least 1 (MPack asserts both);
  C. in a (buffer, size, count) triple (`mpack_reader_init(reader, buffer, size, count)`) the bytes
     already in the buffer are at most its size;
  D. an enum argument (`mpack_type_to_string(mpack_type_t)`) is one of the enum's declared
     constants, which the layout probe reads from the headers;
  E. a realloc-like function (`mpack_realloc(old_ptr, used_size, new_size)`) gets a pointer the
     harness allocated, never a static buffer;
  F. a heap result the caller owns (`mpack_expect_cstr_alloc`, the growable writer's `*target_data`)
     is freed after the call.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import api_harness as ah

pytestmark = pytest.mark.unit

AD_SPARE = ah.spare_bytes(64)

# name -> (signature, [(formal, kind)], call sites)
AD_RECS: dict[str, tuple[str, list[tuple[str, str]], list[str]]] = {
    "rd_init": (
        "void(struct rd *,char *,unsigned long)",
        [("r", "pointer"), ("data", "const_pointer"), ("n", "value")],
        [],
    ),
    "rd_destroy": ("void(struct rd *)", [("r", "pointer")], []),
    # A: ordered pairs.
    "rd_u8_range": (
        "unsigned char(struct rd *,unsigned char,unsigned char)",
        [("r", "pointer"), ("min_value", "value"), ("max_value", "value")],
        [],
    ),
    "rd_double_range": (
        "double(struct rd *,double,double)",
        [("r", "pointer"), ("min_value", "value"), ("max_value", "value")],
        [],
    ),
    # A': one bound forwarded to a range with a constant other bound (mpack_expect_i8_max calls
    # mpack_expect_i8_range(reader, 0, max_value)), as the probe reads the inline body.
    "rd_i8_max": (
        "signed char(struct rd *,signed char)",
        [("r", "pointer"), ("max_value", "value")],
        ["rd_i8_range"],
    ),
    "rd_u8_max": (
        "unsigned char(struct rd *,unsigned char)",
        [("r", "pointer"), ("max_value", "value")],
        ["rd_u8_range"],
    ),
    "rd_double_min": (
        "double(struct rd *,double)",
        [("r", "pointer"), ("min_value", "value")],
        ["rd_double_range"],
    ),
    "clampi": ("int(int,int,int)", [("v", "value"), ("lo", "value"), ("hi", "value")], []),
    "addi": ("int(int,int)", [("a", "value"), ("b", "value")], []),
    # B: NUL-terminated output capacity; a byte copy may take 0.
    "rd_copy_cstr": (
        "void(struct rd *,char *,unsigned long)",
        [("r", "pointer"), ("buffer", "pointer"), ("bufsize", "value")],
        [],
    ),
    "rd_copy_data": (
        "unsigned long(struct rd *,char *,unsigned long)",
        [("r", "pointer"), ("buffer", "pointer"), ("bufsize", "value")],
        [],
    ),
    # B: limits of a limit setter and of a function forwarding them to it; a `max_*` elsewhere (0 may
    # mean "unlimited", as mpack_tree_init_stdfile's max_bytes) is left alone.
    "tr_init_stream": (
        "void(struct tr *,void *,unsigned long,unsigned long)",
        [("t", "pointer"), ("context", "pointer"), ("max_message_size", "value"), ("max_message_nodes", "value")],
        ["tr_set_limits"],
    ),
    "tr_init_file": (
        "void(struct tr *,void *,unsigned long)",
        [("t", "pointer"), ("context", "pointer"), ("max_bytes", "value")],
        [],
    ),
    "tr_set_limits": (
        "void(struct tr *,unsigned long,unsigned long)",
        [("t", "pointer"), ("max_message_size", "value"), ("max_message_nodes", "value")],
        [],
    ),
    "tr_peek": ("int(struct tr *,unsigned long)", [("t", "pointer"), ("max_depth", "value")], []),
    # C: (buffer, size, count) an initializer records; an operation must check its own count.
    "rd_init_buf": (
        "void(struct rd *,char *,unsigned long,unsigned long)",
        [("r", "pointer"), ("buffer", "pointer"), ("size", "value"), ("count", "value")],
        [],
    ),
    "rd_read_cstr": (
        "void(struct rd *,char *,unsigned long,unsigned long)",
        [("r", "pointer"), ("buf", "pointer"), ("buffer_size", "value"), ("byte_count", "value")],
        [],
    ),
    # D: enums by value.
    "type_name": ("char *(enum ty)", [("type", "value")], []),
    "flag_name": ("char *(enum fl)", [("flags", "value")], []),
    # E: realloc-like.
    "my_realloc": (
        "void *(void *,unsigned long,unsigned long)",
        [("old_ptr", "pointer"), ("used_size", "value"), ("new_size", "value")],
        ["realloc"],
    ),
    # F: owned heap results.
    "rd_cstr_alloc": (
        "char *(struct rd *,unsigned long)",
        [("r", "pointer"), ("maxsize", "value")],
        ["rd_bytes_alloc_impl"],
    ),
    "rd_bytes_alloc_impl": (
        "char *(struct rd *,unsigned long,_Bool)",
        [("r", "pointer"), ("count", "value"), ("null_terminated", "value")],
        ["malloc", "free"],
    ),
    # Named like an allocation, but nothing it calls allocates: a pool slot, never freed.
    "rd_pool_alloc": ("char *(struct rd *,unsigned long)", [("r", "pointer"), ("count", "value")], []),
    # Allocates, but the header returns `const char *`: a borrowed string.
    "rd_name_alloc": ("char *(struct rd *)", [("r", "pointer")], ["malloc"]),
    "wr_init_growable": (
        "void(struct wr *,char **,unsigned long *)",
        [("w", "pointer"), ("target_data", "pointer"), ("target_size", "pointer")],
        ["malloc"],
    ),
    "wr_destroy": ("int(struct wr *)", [("w", "pointer")], ["free"]),
}

AD_LAYOUTS = {
    t: {"what": "struct", "size": 32, "align": 8, "pointers": False, "fields": []}
    for t in ("struct rd", "struct tr", "struct wr")
}

# What the layout probe reads from the headers (`param_enums`, `const_returns`).
AD_ENUMS = {"type_name": {0: ["TY_NIL", "TY_INT", "TY_STR"]}}
AD_CONST_RETURNS = {"type_name", "flag_name", "rd_name_alloc"}
# `bound_forwards`: a lone bound a function forwards to a range-like callee with a constant other bound.
AD_BOUNDS = {
    "rd_i8_max": {1: (">=", "0")},
    "rd_u8_max": {1: (">=", "0")},
    "rd_double_min": {1: ("<=", "100.5")},
}


def _ad_plan(
    recs: dict[str, tuple[str, list[tuple[str, str]], list[str]]] | None = None,
    enums: dict[str, dict[int, list[str]]] | None = None,
    probed: bool = True,
) -> dict[str, Any]:
    recs = recs or AD_RECS
    functions = {n: {"name": n, "file": "lib.c", "is_static": False, "module": "lib"} for n in recs}
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": list(recs), "functions": list(recs)}},
        "functions": functions,
    }
    model = {
        "status": "ok",
        "functions": {
            f"lib.c#{n}": {
                "name": n,
                "signature": sig,
                "formals": [{"name": a, "kind": k} for a, k in formals],
                "call_sites": calls,
            }
            for n, (sig, formals, calls) in recs.items()
        },
    }
    if not probed:
        return ah.plan(dag, model, "lib", "lib", 64)
    declared = ah.Declared(
        set(recs),
        {},
        None,
        None,
        None,
        enum_params=AD_ENUMS if enums is None else enums,
        const_returns=AD_CONST_RETURNS,
        bound_forwards=AD_BOUNDS,
    )
    return ah.plan(dag, model, "lib", "lib", 64, None, None, AD_LAYOUTS, declared)


def _ad_case(p: dict[str, Any], entry: str) -> tuple[str, dict[str, Any]]:
    for text, lay in zip(p["cases"], p["layouts"], strict=True):
        if lay.get("entry") == f"lib.c#{entry}" or lay.get("entry") == entry:
            return text, lay
    raise AssertionError(f"no case for {entry}: {p['skipped']}")


def _call_at(text: str, fn: str) -> int:
    m = re.search(rf"\b{fn}\(", text)
    assert m, text
    return m.start()


@pytest.fixture(scope="module")
def ad_plan() -> dict[str, Any]:
    return _ad_plan()


# --- A: (min, max) pairs ---------------------------------------------------------------------------


def test_an_integer_min_max_pair_is_ordered_before_the_call(ad_plan):
    text, lay = _ad_case(ad_plan, "rd_u8_range")
    swap = "if (c0a2 < c0a1) { unsigned char fc_t = c0a1; c0a1 = c0a2; c0a2 = fc_t; }"
    assert swap in text, text
    assert text.index(swap) < _call_at(text, "rd_u8_range")
    # Both bounds are still read from the input, as before.
    assert [s["param"] for s in lay["slots"] if s["call"] == 0] == [1, 2], lay
    assert any("ordered" in n for n in lay.get("notes") or []), lay


def test_a_floating_range_replaces_nan_bounds_then_orders(ad_plan):
    text, _ = _ad_case(ad_plan, "rd_double_range")
    assert "if (c0a1 != c0a1) { c0a1 = 0; }" in text, text
    assert "if (c0a2 != c0a2) { c0a2 = c0a1; }" in text, text
    assert "if (c0a2 < c0a1) { double fc_t = c0a1; c0a1 = c0a2; c0a2 = fc_t; }" in text, text


def test_a_lone_bound_forwarded_to_a_range_keeps_the_constant_other_bound(ad_plan):
    # mpack run-4, verify-mpack_expect_i8_range_6856d80f4e: mpack_expect_i8_max(reader, -1) calls
    # mpack_expect_i8_range(reader, 0, -1), whose `min_value <= max_value` assert is a UBSan unreachable.
    text, lay = _ad_case(ad_plan, "rd_i8_max")
    assert "if (c0a1 < 0) { c0a1 = 0; }" in text, text
    assert text.index("if (c0a1 < 0)") < _call_at(text, "rd_i8_max")
    assert [s["param"] for s in lay["slots"] if s["call"] == 0] == [1], lay
    assert any("forwarded" in n for n in lay.get("notes") or []), lay
    # The mirror: a lone lower bound under a constant upper bound; NaN replaced first.
    text, _ = _ad_case(ad_plan, "rd_double_min")
    assert "if (c0a1 != c0a1) { c0a1 = 100.5; }" in text, text
    assert "if (c0a1 > 100.5) { c0a1 = 100.5; }" in text, text


def test_an_unsigned_bound_above_zero_needs_no_rewrite(ad_plan):
    text, _ = _ad_case(ad_plan, "rd_u8_max")
    assert "c0a1 < 0" not in text, text


def test_a_lone_max_that_is_forwarded_to_no_range_is_not_clamped_by_the_bound_rule(ad_plan):
    # A limit (0 may mean "unlimited", as mpack_tree_init_stdfile's max_bytes) is not a range bound.
    for fn, var in (("tr_init_file", "c0a2"), ("tr_peek", "c0a1")):
        text, _ = _ad_case(ad_plan, fn)
        assert f"if ({var} < 0)" not in text and f"{var} < 1" not in text, (fn, text)


def _bf_call(callee: str, *args: dict[str, Any]) -> dict[str, Any]:
    fn_ref = {
        "kind": "ImplicitCastExpr",
        "inner": [
            {"kind": "DeclRefExpr", "referencedDecl": {"id": f"f_{callee}", "kind": "FunctionDecl", "name": callee}}
        ],
    }
    return {"kind": "CallExpr", "inner": [fn_ref, *args]}


def _bf_parm_ref(pid: str, name: str) -> dict[str, Any]:
    ref = {"kind": "DeclRefExpr", "referencedDecl": {"id": pid, "kind": "ParmVarDecl", "name": name}}
    return {"kind": "ImplicitCastExpr", "castKind": "LValueToRValue", "inner": [ref]}


def _bf_int(value: str) -> dict[str, Any]:
    return {"kind": "ImplicitCastExpr", "inner": [{"kind": "IntegerLiteral", "value": value}]}


def _bf_fn(name: str, parms: list[tuple[str, str]], body: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    inner: list[dict[str, Any]] = [
        {"kind": "ParmVarDecl", "id": pid, "name": pname, "type": {"qualType": "int"}} for pid, pname in parms
    ]
    if body is not None:
        inner.append({"kind": "CompoundStmt", "inner": [{"kind": "ReturnStmt", "inner": body}]})
    return {"kind": "FunctionDecl", "name": name, "type": {"qualType": "int (int, int)"}, "inner": inner}


def test_bound_forwards_reads_an_inline_body_of_the_clang_ast():
    rng = _bf_fn("i8_range", [("p0", "reader"), ("p1", "min_value"), ("p2", "max_value")])
    lone_max = _bf_fn(
        "i8_max",
        [("q0", "reader"), ("q1", "max_value")],
        [_bf_call("i8_range", _bf_parm_ref("q0", "reader"), _bf_int("0"), _bf_parm_ref("q1", "max_value"))],
    )
    neg = {"kind": "UnaryOperator", "opcode": "-", "inner": [{"kind": "IntegerLiteral", "value": "5"}]}
    lone_min = _bf_fn(
        "i8_min",
        [("s0", "reader"), ("s1", "min_value")],
        [_bf_call("i8_range", _bf_parm_ref("s0", "reader"), _bf_parm_ref("s1", "min_value"), neg)],
    )
    # Both bounds forwarded (rule A covers the pair), a cast bound (its value may change), and a call
    # to a function with no range pair: none gives a bound.
    both = _bf_fn(
        "i8_both",
        [("t0", "reader"), ("t1", "lo"), ("t2", "hi")],
        [_bf_call("i8_range", _bf_parm_ref("t0", "reader"), _bf_parm_ref("t1", "lo"), _bf_parm_ref("t2", "hi"))],
    )
    cast = {"kind": "CStyleCastExpr", "inner": [_bf_parm_ref("u1", "max_value")]}
    casted = _bf_fn(
        "i8_cast",
        [("u0", "reader"), ("u1", "max_value")],
        [_bf_call("i8_range", _bf_parm_ref("u0", "reader"), _bf_int("0"), cast)],
    )
    put = _bf_fn("put", [("v0", "reader"), ("v1", "a"), ("v2", "b")])
    other = _bf_fn(
        "put_max",
        [("w0", "reader"), ("w1", "max_bytes")],
        [_bf_call("put", _bf_parm_ref("w0", "reader"), _bf_int("0"), _bf_parm_ref("w1", "max_bytes"))],
    )
    tree = {"kind": "TranslationUnitDecl", "inner": [rng, lone_max, lone_min, both, casted, put, other]}
    assert ah.bound_forwards(tree) == {"i8_max": {1: (">=", "0")}, "i8_min": {1: ("<=", "-5")}}
    _, declared = ah.record_layouts(tree)
    assert isinstance(declared, ah.Declared)
    assert declared.bound_forwards == {"i8_max": {1: (">=", "0")}, "i8_min": {1: ("<=", "-5")}}


def test_lo_hi_is_a_range_and_two_unrelated_integers_are_not(ad_plan):
    text, _ = _ad_case(ad_plan, "clampi")
    assert "if (c0a2 < c0a1) { int fc_t = c0a1; c0a1 = c0a2; c0a2 = fc_t; }" in text, text
    text, _ = _ad_case(ad_plan, "addi")
    assert "fc_t" not in text, text


# --- B: capacities and limits at least 1 -----------------------------------------------------------


def test_a_nul_terminated_output_capacity_is_at_least_one(ad_plan):
    text, lay = _ad_case(ad_plan, "rd_copy_cstr")
    assert f"if ((unsigned long long)c0a2 > {AD_SPARE}ULL)" in text, text
    assert "if (c0a2 < 1) { c0a2 = 1; }" in text, text
    assert text.index("if (c0a2 < 1)") < _call_at(text, "rd_copy_cstr")
    assert [s["param"] for s in lay["slots"] if s["call"] == 0] == [2], lay


def test_a_byte_copy_may_still_get_a_zero_capacity(ad_plan):
    text, _ = _ad_case(ad_plan, "rd_copy_data")
    assert "c0a2 < 1" not in text, text


def test_the_limits_of_an_initializer_and_a_limit_setter_are_at_least_one(ad_plan):
    text, _ = _ad_case(ad_plan, "tr_init_stream")
    # max_message_size is read as the length after `void *context`, and still gets the rule.
    assert "if (c0a2 < 1) { c0a2 = 1; }" in text, text
    assert "if (c0a3 < 1) { c0a3 = 1; }" in text, text
    text, _ = _ad_case(ad_plan, "tr_set_limits")
    assert "if (c0a1 < 1) { c0a1 = 1; }" in text, text
    assert "if (c0a2 < 1) { c0a2 = 1; }" in text, text
    # A `max_*` of another function is left alone.
    for fn, var in (("tr_peek", "c0a1"), ("tr_init_file", "c0a2")):
        text, _ = _ad_case(ad_plan, fn)
        assert f"{var} < 1" not in text, (fn, text)


# --- C: (buffer, size, count) ---------------------------------------------------------------------


def test_the_count_of_a_buffer_size_count_triple_is_at_most_the_size(ad_plan):
    text, lay = _ad_case(ad_plan, "rd_init_buf")
    clamp = "if ((unsigned long long)c0a3 > (unsigned long long)c0a2) { c0a3 = (unsigned long)c0a2; }"
    assert clamp in text, text
    assert text.index(f"if ((unsigned long long)c0a2 > {AD_SPARE}ULL)") < text.index(clamp)
    assert text.index(clamp) < _call_at(text, "rd_init_buf")
    assert [s["param"] for s in lay["slots"] if s["call"] == 0] == [2, 3], lay


def test_an_operation_keeps_a_count_larger_than_its_buffer(ad_plan):
    # mpack_read_cstr flags mpack_error_too_big for such a count: a check the fuzzer exercises.
    text, _ = _ad_case(ad_plan, "rd_read_cstr")
    assert "(unsigned long long)c0a3 >" not in text, text
    # Its NUL-terminated output still needs room for the terminator.
    assert "if (c0a2 < 1) { c0a2 = 1; }" in text, text


# --- D: enums ------------------------------------------------------------------------------------


def test_an_enum_argument_is_mapped_onto_the_declared_constants(ad_plan):
    text, lay = _ad_case(ad_plan, "type_name")
    # A declared value is kept; any other is mapped onto one of them.
    member = " || ".join(f"(long long)c0a0 == (long long){c}" for c in ("TY_NIL", "TY_INT", "TY_STR"))
    assert f"if (!({member})) {{ static const long long fc_e[3] = {{ TY_NIL, TY_INT, TY_STR }}; " in text, text
    assert "c0a0 = (int)fc_e[(unsigned int)c0a0 % 3U]; }" in text, text
    assert text.index("fc_e[3]") < _call_at(text, "type_name")
    assert lay["slots"] == [{"call": 0, "param": 0, "size": 4, "kind": "int"}]


def test_an_enum_with_no_known_constants_is_left_as_read_and_said_so(ad_plan):
    text, lay = _ad_case(ad_plan, "flag_name")
    assert "fc_e" not in text, text
    assert any("enum" in n for n in lay.get("notes") or []), lay


@pytest.mark.parametrize("fixture_tree", ["named", "typedef_anon"])
def test_param_enums_reads_the_constants_from_the_clang_ast(fixture_tree: str):
    enum_id = "0x1"
    consts = [
        {"kind": "EnumConstantDecl", "name": "K_A"},
        {"kind": "EnumConstantDecl", "name": "K_B", "inner": [{"kind": "ConstantExpr", "value": "5"}]},
        {"kind": "EnumConstantDecl", "name": "K_C"},
    ]
    enum: dict[str, Any]
    typedef: dict[str, Any]
    if fixture_tree == "named":
        enum = {"kind": "EnumDecl", "id": enum_id, "name": "k", "inner": consts}
        typedef = {"kind": "TypedefDecl", "name": "k_t", "type": {"qualType": "enum k"}}
    else:
        enum = {"kind": "EnumDecl", "id": enum_id, "inner": consts}
        typedef = {
            "kind": "TypedefDecl",
            "name": "k_t",
            "type": {"qualType": "k_t"},
            "inner": [{"kind": "ElaboratedType", "ownedTagDecl": {"id": enum_id, "kind": "EnumDecl", "name": ""}}],
        }
    # Flag constants (distinct powers of two) are combined by the caller: no entry.
    flags = {
        "kind": "EnumDecl",
        "id": "0x2",
        "name": "fl",
        "inner": [
            {"kind": "EnumConstantDecl", "name": f"F_{v}", "inner": [{"kind": "ConstantExpr", "value": str(v)}]}
            for v in (1, 2, 4, 8)
        ],
    }
    fn = {
        "kind": "FunctionDecl",
        "name": "use",
        "type": {"qualType": "const char *(k_t, int, enum fl)"},
        "inner": [
            {"kind": "ParmVarDecl", "name": "k", "type": {"qualType": "k_t"}},
            {"kind": "ParmVarDecl", "name": "n", "type": {"qualType": "int"}},
            {"kind": "ParmVarDecl", "name": "f", "type": {"qualType": "enum fl"}},
        ],
    }
    tree = {"kind": "TranslationUnitDecl", "inner": [enum, typedef, flags, fn]}
    assert ah.param_enums(tree) == {"use": {0: ["K_A", "K_B", "K_C"]}}
    assert ah.const_returns(tree) == {"use"}
    _, declared = ah.record_layouts(tree)
    assert isinstance(declared, ah.Declared)
    assert declared.enum_params == {"use": {0: ["K_A", "K_B", "K_C"]}}
    assert declared.const_returns == {"use"}


# --- E: realloc-like -----------------------------------------------------------------------------


def test_a_realloc_like_function_gets_a_heap_pointer_and_its_result_is_freed(ad_plan):
    text, lay = _ad_case(ad_plan, "my_realloc")
    old = ah.REALLOC_OLD_BYTES
    assert f"unsigned char *c0a0 = (unsigned char *)malloc({old});" in text, text
    assert "static _Alignas(16) unsigned char c0a0" not in text, text
    # used_size within the old allocation and the new size; new_size in 1..spare.
    assert f"if ((unsigned long long)c0a1 > {old}ULL) {{ c0a1 = {old}; }}" in text, text
    assert "if ((unsigned long long)c0a1 > (unsigned long long)c0a2) { c0a1 = (unsigned long)c0a2; }" in text, text
    assert f"if (c0a2 < 1 || (unsigned long long)c0a2 > {AD_SPARE}ULL)" in text, text
    call = "void *c0r = (void *)my_realloc((void *)c0a0, c0a1, c0a2);"
    assert call in text, text
    assert "if (c0r != 0) { free(c0r); } else { free(c0a0); }" in text, text
    assert text.index("if (c0a0 != 0) {") < text.index(call)
    assert [s["param"] for s in lay["slots"]] == [1, 2], lay


# --- F: owned heap results ------------------------------------------------------------------------


@pytest.mark.parametrize("fn", ["rd_cstr_alloc", "rd_bytes_alloc_impl"])
def test_an_allocated_result_is_freed(ad_plan, fn: str):
    text, lay = _ad_case(ad_plan, fn)
    assert re.search(rf"void \*c0r = \(void \*\){fn}\(&c0a0, ", text), text
    assert "free(c0r);" in text, text
    assert any("freed" in n for n in lay.get("notes") or []), lay


@pytest.mark.parametrize("fn", ["rd_pool_alloc", "rd_name_alloc"])
def test_a_result_with_no_allocation_or_a_const_one_is_not_freed(ad_plan, fn: str):
    text, _ = _ad_case(ad_plan, fn)
    assert "free(" not in text, text


def test_the_growable_output_is_freed_after_the_destructor(ad_plan):
    text, _ = _ad_case(ad_plan, "wr_init_growable")
    assert "wr_destroy(&c0a0);" in text, text
    assert "free(c0a1);" in text, text
    assert text.index("wr_destroy(&c0a0);") < text.index("free(c0a1);")


def test_the_growable_output_of_an_initializer_run_first_is_freed_after_the_call(ad_plan):
    # wr_destroy's case builds its writer with wr_init_growable (call 1): the destructor under test
    # hands the buffer over, so it is freed after that call, never before.
    text, _ = _ad_case(ad_plan, "wr_destroy")
    assert "wr_init_growable(" in text and "&c1a1" in text, text
    assert text.index("wr_destroy(&c0a0);") < text.index("free(c1a1);"), text


def test_lifecycle_methods_get_the_rules_inside_their_own_branch():
    # A lifecycle case runs a method several times: its normalization and its free belong to the
    # branch that declares its arguments afresh on every run, never once for the whole loop.
    hd = "struct hd *"

    def rec(name: str, sig: str, formals: list[tuple[str, str]]) -> dict[str, Any]:
        return {"name": name, "signature": sig, "formals": [{"name": a, "kind": k} for a, k in formals]}

    recs = {
        "hd_new": rec("hd_new", "struct hd *(void)", []),
        "hd_free": rec("hd_free", "void(struct hd *)", [("h", "pointer")]),
        "hd_range": rec("hd_range", "int(struct hd *,int,int)", [("h", "pointer"), ("lo", "value"), ("hi", "value")]),
        "hd_name_dup": rec("hd_name_dup", "char *(struct hd *)", [("h", "pointer")]),
    }
    api = ah.ApiInfo(
        probed=True,
        records={"hd_new": recs["hd_new"]},
        handles={n: {0: hd} for n in ("hd_free", "hd_range", "hd_name_dup")},
        ctors={hd: "hd_new"},
        dtors={hd: "hd_free"},
        dtor_names={hd: {"hd_free"}},
        returns={"hd_new": hd},
        allocating={"hd_name_dup"},
    )
    stmt, _, why = ah.lifecycle_case(hd, ["hd_range", "hd_name_dup"], recs, AD_SPARE, api)
    assert stmt is not None, why
    branch0 = stmt[stmt.index("if (fc_k == 0U) {") : stmt.index("else if (fc_k == 1U)")]
    assert "if (c1a2 < c1a1) { int fc_t = c1a1; c1a1 = c1a2; c1a2 = fc_t; }" in branch0, stmt
    branch1 = stmt[stmt.index("else if (fc_k == 1U)") :]
    assert "{ void *c2r = (void *)hd_name_dup((struct hd *)fc_h); free(c2r); }" in branch1, stmt


def test_rules_need_the_probe_only_for_enums():
    p = _ad_plan(probed=False)
    text, _ = _ad_case(p, "rd_u8_range")
    assert "fc_t" in text, text
    text, _ = _ad_case(p, "type_name")
    assert "fc_e" not in text, text


# --- end to end: real clang's AST of a library that asserts its preconditions, fuzzed clean ---------

# Each precondition is checked the way MPack's release build does: a violation is
# `__builtin_unreachable()`, which UBSan reports. Leaks and frees of non-heap pointers are ASan's.
AD_LIB_H = """#include <stddef.h>
typedef enum ty { TY_NIL = 1, TY_INT, TY_STR } ty_t;
typedef enum { E_OK, E_IO, E_BUG } err_t;
typedef enum { FL_A = 1 << 0, FL_B = 1 << 1, FL_C = 1 << 2 } fl_t;
const char *fl_name(fl_t flags);
struct rd { const char *data; size_t size; size_t count; };
void rd_init(struct rd *r, char *buffer, size_t size, size_t count);
void rd_destroy(struct rd *r);
unsigned char rd_u8_range(struct rd *r, unsigned char min_value, unsigned char max_value);
double rd_double_range(struct rd *r, double min_value, double max_value);
signed char rd_i8_range(struct rd *r, signed char min_value, signed char max_value);
inline signed char rd_i8_max(struct rd *r, signed char max_value) { return rd_i8_range(r, 0, max_value); }
void rd_copy_cstr(struct rd *r, char *buffer, size_t bufsize);
char *rd_cstr_alloc(struct rd *r, size_t maxsize);
const char *ty_name(ty_t type);
const char *err_name(err_t error);
void *lib_realloc(void *old_ptr, size_t used_size, size_t new_size);
struct wr { char **target; char *buf; };
void wr_init_growable(struct wr *w, char **target_data, size_t *target_size);
void wr_destroy(struct wr *w);
"""

AD_LIB_C = """#include <stdlib.h>
#include <string.h>
#include "lib.h"
#define REQUIRE(c) do { if (!(c)) __builtin_unreachable(); } while (0)
void rd_init(struct rd *r, char *buffer, size_t size, size_t count) {
    REQUIRE(count <= size);
    r->data = buffer; r->size = size; r->count = count;
    if (count) { volatile char last = buffer[count - 1]; (void)last; }
}
void rd_destroy(struct rd *r) { (void)r; }
unsigned char rd_u8_range(struct rd *r, unsigned char min_value, unsigned char max_value) {
    REQUIRE(min_value <= max_value);
    return r->count ? max_value : min_value;
}
double rd_double_range(struct rd *r, double min_value, double max_value) {
    REQUIRE(min_value <= max_value);
    return r->count ? max_value : min_value;
}
signed char rd_i8_range(struct rd *r, signed char min_value, signed char max_value) {
    REQUIRE(min_value <= max_value);
    return r->count ? max_value : min_value;
}
extern inline signed char rd_i8_max(struct rd *r, signed char max_value);
void rd_copy_cstr(struct rd *r, char *buffer, size_t bufsize) {
    REQUIRE(bufsize >= 1);
    size_t n = r->count < bufsize - 1 ? r->count : bufsize - 1;
    if (n) memcpy(buffer, r->data, n);
    buffer[n] = 0;
}
char *rd_cstr_alloc(struct rd *r, size_t maxsize) {
    (void)r;
    char *s = malloc(maxsize % 32 + 1);
    if (s) s[0] = 0;
    return s;
}
const char *ty_name(ty_t type) {
    switch (type) { case TY_NIL: return "nil"; case TY_INT: return "int"; case TY_STR: return "str"; }
    __builtin_unreachable();
}
const char *err_name(err_t error) {
    switch (error) { case E_OK: return "ok"; case E_IO: return "io"; case E_BUG: return "bug"; }
    __builtin_unreachable();
}
const char *fl_name(fl_t flags) { return (flags & FL_B) ? "b" : "-"; }
void *lib_realloc(void *old_ptr, size_t used_size, size_t new_size) {
    if (new_size == 0) { free(old_ptr); return NULL; }
    void *p = malloc(new_size);
    if (p == NULL) return NULL;
    if (used_size) memcpy(p, old_ptr, used_size);
    free(old_ptr);
    return p;
}
void wr_init_growable(struct wr *w, char **target_data, size_t *target_size) {
    *target_data = NULL; *target_size = 0;
    w->target = target_data; w->buf = malloc(16);
}
void wr_destroy(struct wr *w) { if (w->buf) { *w->target = w->buf; w->buf = NULL; } }
"""

AD_AST_SCRIPT = "cd /fixture && clang -fsyntax-only -x c -Xclang -ast-dump=json lib.h"

AD_RUN_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g -I. harness.c lib.c -o fz || exit 1
mkdir corpus
timeout 300 ./fz -runs=200000 -seed=11 -max_len=64 -detect_leaks=1 corpus > fz.log 2>&1 && echo FUZZ_CLEAN || tail -40 fz.log
"""

# The model of AD_LIB_C as Phase 0 records it: signatures without `const`, enums by tag, call sites.
AD_E2E_RECS: dict[str, tuple[str, list[tuple[str, str]], list[str]]] = {
    "rd_init": (
        "void(struct rd *,char *,unsigned long,unsigned long)",
        [("r", "pointer"), ("buffer", "pointer"), ("size", "value"), ("count", "value")],
        [],
    ),
    "rd_destroy": ("void(struct rd *)", [("r", "pointer")], []),
    "rd_u8_range": AD_RECS["rd_u8_range"],
    "rd_double_range": AD_RECS["rd_double_range"],
    "rd_i8_range": (
        "signed char(struct rd *,signed char,signed char)",
        [("r", "pointer"), ("min_value", "value"), ("max_value", "value")],
        [],
    ),
    "rd_i8_max": AD_RECS["rd_i8_max"],
    "rd_copy_cstr": AD_RECS["rd_copy_cstr"],
    "rd_cstr_alloc": ("char *(struct rd *,unsigned long)", [("r", "pointer"), ("maxsize", "value")], ["malloc"]),
    "ty_name": ("char *(enum ty)", [("type", "value")], []),
    "err_name": ("char *(enum __anonenum_err_t_1)", [("error", "value")], []),
    "fl_name": ("char *(enum __anonenum_fl_t_2)", [("flags", "value")], []),
    "lib_realloc": (
        "void *(void *,unsigned long,unsigned long)",
        [("old_ptr", "pointer"), ("used_size", "value"), ("new_size", "value")],
        ["malloc", "free"],
    ),
    "wr_init_growable": AD_RECS["wr_init_growable"],
    "wr_destroy": ("void(struct wr *)", [("w", "pointer")], []),
}


def _ad_docker(tmp_path: Any, script: str, image: str) -> Any:
    import os
    import subprocess

    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-api-arg-domains")
    argv = [
        "docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
        "-v", f"{tmp_path}:/fixture:ro", image, script,
    ]  # fmt: skip
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)


@pytest.mark.integration
def test_cases_respect_the_preconditions_of_a_real_header_and_fuzz_clean(tmp_path):
    import json
    from pathlib import Path

    import generate_harness as gh
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "lib.h").write_text(AD_LIB_H, encoding="utf-8")
    (tmp_path / "lib.c").write_text(AD_LIB_C, encoding="utf-8")
    ast = _ad_docker(tmp_path, AD_AST_SCRIPT, ANALYSIS_IMAGE)
    assert ast.returncode == 0, ast.stderr[-2000:]
    layouts, declared = ah.record_layouts(json.loads(ast.stdout))
    assert isinstance(declared, ah.Declared)
    assert declared.enum_params["ty_name"] == {0: ["TY_NIL", "TY_INT", "TY_STR"]}
    assert declared.enum_params["err_name"] == {0: ["E_OK", "E_IO", "E_BUG"]}
    # A flag enum (`1 << n` initializers, evaluated by clang) is left as read: callers combine them.
    assert "fl_name" not in declared.enum_params, declared.enum_params
    # The inline wrapper's body, as real clang dumps it: its lone upper bound stays >= 0.
    assert declared.bound_forwards == {"rd_i8_max": {1: (">=", "0")}}, declared.bound_forwards
    recs = AD_E2E_RECS
    functions = {n: {"name": n, "file": "lib.c", "is_static": False, "module": "lib"} for n in recs}
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": list(recs), "functions": list(recs)}},
        "functions": functions,
    }
    model = {
        "status": "ok",
        "functions": {
            f"lib.c#{n}": {
                "name": n,
                "signature": s,
                "formals": [{"name": a, "kind": k} for a, k in f],
                "call_sites": c,
            }
            for n, (s, f, c) in recs.items()
        },
    }
    p = ah.plan(dag, model, "lib", "lib", 64, None, None, layouts, declared)
    assert p["skipped"] == {}, p["skipped"]
    inv = gh._build_dispatch_invocation(p["cases"])
    text = (Path(__file__).resolve().parents[1] / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "lib",
        "MODULE_HEADER": "lib.h",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    (tmp_path / "harness.c").write_text(text, encoding="utf-8")
    proc = _ad_docker(tmp_path, AD_RUN_SCRIPT, ANALYSIS_IMAGE)
    assert "FUZZ_CLEAN" in proc.stdout, (proc.stdout + proc.stderr)[-4000:]
