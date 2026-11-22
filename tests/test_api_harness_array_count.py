"""An `--api` case backs a (T *array, count) parameter pair with an array (mpack run-3, S12).

`mpack_expect_enum(mpack_reader_t *, const char *strings[], size_t count)` got one `const char *`
object (`&c0a1`) and a count read straight from the input: any count above 1 read past the one
element, a crash the Crash Verifier rejected as harness_induced. A pointer to non-byte elements
followed by a count-named integer now gets ARRAY_ELEMENTS valid elements and a count mapped into
1..ARRAY_ELEMENTS (never 0: `mpack_expect_enum_optional` asserts `count != 0`, which is
`__builtin_unreachable()` in a release build). The count's slot and the case's layout stay as they
were, so selectors and seeds do not move. Byte (buffer, length) pairs are unchanged.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import api_harness as ah

pytestmark = pytest.mark.unit

N = getattr(ah, "ARRAY_ELEMENTS", 4)

RECS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    # mpack_expect_enum's shape: the model drops the nested const (`char **`).
    "pick": (
        "unsigned long(struct ctx *,char **,unsigned long)",
        [("c", "pointer"), ("names", "pointer"), ("count", "value")],
    ),
    # An array of scalars the call only reads.
    "sum": ("int(struct ctx *,int *,unsigned long)", [("c", "pointer"), ("vals", "const_pointer"), ("n", "value")]),
    # A pointer and a value: no count.
    "put": ("void(int *,unsigned int)", [("dst", "pointer"), ("value", "value")]),
    # A byte (buffer, length) pair the call writes.
    "fill": ("int(char *,unsigned long)", [("out", "pointer"), ("n", "value")]),
}
# The layout probe's spelling of pick's `const char *names[]` (qualified_pointer_spellings).
QUAL = {"pick": {1: {"type": "const char **", "pointee": "const char *"}}}


def _plan(
    recs: dict[str, tuple[str, list[tuple[str, str]]]],
    qual: dict[str, dict[int, dict[str, str]]] | None = None,
    sizes: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
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
                **({"param_sizes": sizes[n]} if sizes and n in sizes else {}),
            }
            for n, (sig, formals) in recs.items()
        },
    }
    layouts = {"struct ctx": {"what": "struct", "size": 16, "align": 8, "pointers": False, "fields": []}}
    declared = ah.Declared(set(recs), {}, None, None, qual or {})
    return ah.plan(dag, model, "lib", "lib", 64, None, None, layouts, declared)


def _case(p: dict[str, Any], entry: str) -> tuple[str, dict[str, Any]]:
    for text, lay in zip(p["cases"], p["layouts"], strict=True):
        if lay.get("entry") == entry:
            return text, lay
    raise AssertionError(f"no case for {entry}: {p['skipped']}")


def _clamp(var: str, n: str) -> str:
    return f"1ULL + ((unsigned long long){var} % {n} + ({n} - 1ULL)) % {n}"


@pytest.mark.parametrize("count", [0, 1, 2, 3, 4, 5, 1000, 2**64 - 1])
def test_the_count_mapping_keeps_1_to_n_and_never_wraps(count: int):
    # The C expression, evaluated on unsigned long long: no intermediate leaves 0..2**64-1.
    m = 2**64
    inner = count % N + (N - 1)
    assert 0 <= inner < m
    got = (1 + inner % N) % m
    assert 1 <= got <= N
    if 1 <= count <= N:
        assert got == count


def test_a_string_array_gets_valid_elements_and_a_bounded_count():
    text, lay = _case(_plan(RECS, QUAL), "pick")
    # An array of N `const char *`, every element a NUL-terminated string, passed as the array.
    assert re.search(rf"const char \* ?c0a1\[{N}\];", text), text
    for k in range(N):
        assert f"c0a1[{k}] = " in text, (k, text)
    assert "&c0a1" not in text, text
    assert "(const char **)c0a1" in text, text
    # The count is mapped into 1..N before the call.
    assert _clamp("c0a2", f"{N}ULL") in text, text
    assert text.index(_clamp("c0a2", f"{N}ULL")) < text.index("pick(")
    assert any("1.." in n for n in lay.get("notes") or []), lay


def test_the_string_elements_are_distinct_strings():
    text, _ = _case(_plan(RECS, QUAL), "pick")
    lits = re.findall(r'memcpy\(c0a1s\[\d\], ("[^"]*")', text)
    assert len(set(lits)) == len(lits) and lits, text


def test_the_string_array_keeps_its_layout():
    # Only the count is read from the input, as before: selectors and seeds do not move.
    _, lay = _case(_plan(RECS, QUAL), "pick")
    assert lay["slots"] == [{"call": 0, "param": 2, "size": 8, "kind": "int"}]
    assert lay["rest"] is None


def test_a_scalar_array_gets_n_elements_and_a_bounded_count():
    text, lay = _case(_plan(RECS), "sum")
    assert f"int c0a1[{N}];" in text, text
    assert "&c0a1" not in text.split("sum(")[1], text
    assert _clamp("c0a2", f"{N}ULL") in text, text
    # Element 0 is read from the input as the one object was: the layout is unchanged.
    assert lay["slots"] == [
        {"call": 0, "param": 1, "size": 4, "kind": "pointee"},
        {"call": 0, "param": 2, "size": 8, "kind": "int"},
    ]


def test_an_array_of_known_size_bounds_the_count_by_its_elements():
    sizes = {"sum": {"1": {"min": 24, "max": 24}}}
    text, _ = _case(_plan(RECS, sizes=sizes), "sum")
    assert "int c0a1[(24 + sizeof(int) - 1) / sizeof(int)]" in text, text
    assert _clamp("c0a2", "(sizeof(c0a1) / sizeof(c0a1[0]))") in text, text


def test_a_pointer_and_a_value_is_no_array():
    # No count: `value` is no element count and stays as read. The pointer is a small zeroed array
    # (`_scalar_array`), which a callee that writes one `int` never notices.
    text, lay = _case(_plan(RECS), "put")
    assert f"int c0a0[{N}];" in text and "&c0a0" not in text, text
    assert "% " not in text and "c0a1 = " not in text, text
    assert lay["slots"] == [{"call": 0, "param": 1, "size": 4, "kind": "int"}]


def test_a_byte_pair_is_unchanged():
    text, lay = _case(_plan(RECS), "fill")
    spare = ah.spare_bytes(64)
    assert f"if ((unsigned long long)c0a1 > {spare}ULL) {{ c0a1 = (unsigned long){spare}; }}" in text, text
    assert "% " not in text, text
    assert lay["slots"] == [{"call": 0, "param": 1, "size": 8, "kind": "int"}]


def test_an_array_spelled_with_brackets_is_an_array_of_its_elements():
    recs = {
        "pick2": (
            "unsigned long(struct ctx *,char *[],unsigned long)",
            [("c", "pointer"), ("names", "pointer"), ("count", "value")],
        ),
        # A byte array spelled with brackets stays a (buffer, length) pair.
        "fill2": ("int(char [],unsigned long)", [("out", "pointer"), ("n", "value")]),
    }
    p = _plan(recs)
    text, _ = _case(p, "pick2")
    assert re.search(rf"char \* ?c0a1\[{N}\];", text), text
    assert _clamp("c0a2", f"{N}ULL") in text, text
    text, _ = _case(p, "fill2")
    assert "unsigned char c0a0[" in text and "% " not in text, text


def test_pointer_elements_are_never_read_from_the_input():
    recs = {
        "names_in": ("int(char **,unsigned long)", [("names", "const_pointer"), ("count", "value")]),
        "ptr_in": ("int(char **)", [("name", "const_pointer")]),
    }
    p = _plan(recs)
    for entry in recs:
        _, lay = _case(p, entry)
        assert all(s["param"] != 0 for s in lay["slots"]), (entry, lay)


def test_arrays_that_share_one_count_all_get_elements():
    # mpack_expect_key_cstr(reader, const char *keys[], bool found[], size_t count): both arrays hold
    # `count` elements.
    recs = {
        "keys": (
            "unsigned long(struct ctx *,char **,_Bool *,unsigned long)",
            [("c", "pointer"), ("keys", "pointer"), ("found", "pointer"), ("count", "value")],
        ),
    }
    qual = {"keys": {1: {"type": "const char **", "pointee": "const char *"}}}
    text, lay = _case(_plan(recs, qual), "keys")
    assert re.search(rf"const char \* ?c0a1\[{N}\];", text), text
    assert f"_Bool c0a2[{N}];" in text, text
    assert "(const char **)c0a1" in text and "(_Bool *)c0a2" in text, text
    assert _clamp("c0a3", f"{N}ULL") in text, text
    assert lay["slots"] == [{"call": 0, "param": 3, "size": 8, "kind": "int"}]


def test_only_the_last_array_of_a_group_may_point_to_a_struct():
    # A struct pointer before another pointer is no array: `c` stays one object.
    recs = {
        "walk": ("int(struct pt *,int *,unsigned long)", [("c", "pointer"), ("vals", "pointer"), ("count", "value")])
    }
    text, _ = _case(_plan(recs), "walk")
    assert "struct pt c0a0;" in text and f"int c0a1[{N}];" in text, text


def test_a_count_named_signed_integer_and_struct_elements():
    recs = {
        "points": ("int(struct pt *,int)", [("pts", "const_pointer"), ("num_pts", "value")]),
        # A struct pointer and a `size`: a context and its size, not an array of contexts.
        "ctx_set": ("int(struct pt *,unsigned long)", [("p", "pointer"), ("size", "value")]),
    }
    p = _plan(recs)
    text, _ = _case(p, "points")
    assert f"struct pt c0a0[{N}];" in text, text
    assert "(int)(" + _clamp("c0a1", f"{N}ULL") + ")" in text, text
    text, _ = _case(p, "ctx_set")
    assert "% " not in text, text


# --- libmodbus run-1: buffers with no length, indexed by an index and a count -----------------------

# The model's signatures and formals of libmodbus's data helpers and register calls (the context is a
# `struct ctx *` here: the fixture has no layout probe, so no handle).
MODBUS_RECS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "modbus_get_float_abcd": ("float(unsigned short *)", [("src", "const_pointer")]),
    "modbus_set_float_abcd": ("void(float,unsigned short *)", [("f", "value"), ("dest", "pointer")]),
    "modbus_get_byte_from_bits": (
        "unsigned char(unsigned char *,int,unsigned int)",
        [("src", "const_pointer"), ("idx", "value"), ("nb_bits", "value")],
    ),
    "modbus_set_bits_from_byte": (
        "void(unsigned char *,int,unsigned char)",
        [("dest", "pointer"), ("idx", "value"), ("value", "value")],
    ),
    "modbus_set_bits_from_bytes": (
        "void(unsigned char *,int,unsigned int,unsigned char *)",
        [("dest", "pointer"), ("idx", "value"), ("nb_bits", "value"), ("tab_byte", "const_pointer")],
    ),
    "modbus_read_bits": (
        "int(struct ctx *,int,int,unsigned char *)",
        [("ctx", "pointer"), ("addr", "value"), ("nb", "value"), ("dest", "pointer")],
    ),
    "modbus_write_registers": (
        "int(struct ctx *,int,int,unsigned short *)",
        [("ctx", "pointer"), ("addr", "value"), ("nb", "value"), ("src", "const_pointer")],
    ),
    "modbus_write_and_read_registers": (
        "int(struct ctx *,int,int,unsigned short *,int,int,unsigned short *)",
        [
            ("ctx", "pointer"),
            ("write_addr", "value"),
            ("write_nb", "value"),
            ("src", "const_pointer"),
            ("read_addr", "value"),
            ("read_nb", "value"),
            ("dest", "pointer"),
        ],
    ),
}


def _bound(var: str, ctype: str, limit: str) -> str:
    return f"if ((unsigned long long){var} > {limit}) {{ {var} = ({ctype})({limit}); }}"


def _half(*bufs: str) -> str:
    n = [f"(sizeof({b}) / sizeof({b}[0]))" for b in bufs]
    m = n[0]
    for x in n[1:]:
        m = f"({m} < {x} ? {m} : {x})"
    return f"{m} / 2ULL"


def test_a_pointer_to_a_scalar_with_no_count_is_a_small_array():
    """
    `modbus_get_float_abcd(const uint16_t *src)` reads `src[0]` and `src[1]`: one `uint16_t` was a
    stack-buffer-overflow READ only the harness made. An unsized pointer to a non-byte scalar is an
    array of ARRAY_ELEMENTS zeroed elements, element 0 read from the input as the one object was.
    """
    p = _plan(MODBUS_RECS)
    text, lay = _case(p, "modbus_get_float_abcd")
    assert f"unsigned short c0a0[{N}]; memset(c0a0, 0, sizeof(c0a0));" in text, text
    assert "modbus_get_float_abcd((unsigned short *)c0a0)" in text and "&c0a0)" not in text, text
    assert "memcpy(&c0a0[0], " in text, text
    assert lay["slots"] == [{"call": 0, "param": 0, "size": 2, "kind": "pointee"}]
    # The writer: `dest[0]` and `dest[1]`, zeroed, never read from the input.
    text, lay = _case(p, "modbus_set_float_abcd")
    assert f"unsigned short c0a1[{N}]; memset(c0a1, 0, sizeof(c0a1));" in text, text
    assert "modbus_set_float_abcd(c0a0, (unsigned short *)c0a1)" in text, text
    assert lay["slots"] == [{"call": 0, "param": 0, "size": 4, "kind": "int"}]


def test_an_index_and_a_count_stay_within_a_buffer_of_no_length():
    """
    `modbus_get_byte_from_bits(src, idx, nb_bits)` reads `src[idx + i]`; `modbus_set_bits_from_bytes(dest,
    idx, nb_bits, tab_byte)` writes `dest[idx .. idx + nb_bits)` and reads `tab_byte[nb_bits / 8]`.
    With no length beside the buffers the callee cannot check them: the caller's contract says they
    fit. An index or a count of such a call is kept within half of the smallest buffer, so an index
    plus a count stays inside it; a value inside is passed as read, and the slots do not move.
    """
    p = _plan(MODBUS_RECS)
    text, lay = _case(p, "modbus_get_byte_from_bits")
    lim = _half("c0a0")
    assert _bound("c0a1", "int", lim) in text, text
    assert _bound("c0a2", "unsigned int", lim) in text, text
    assert text.index(_bound("c0a2", "unsigned int", lim)) < text.index("modbus_get_byte_from_bits(")
    assert lay["slots"] == [
        {"call": 0, "param": 1, "size": 4, "kind": "int"},
        {"call": 0, "param": 2, "size": 4, "kind": "int"},
    ]
    text, _ = _case(p, "modbus_set_bits_from_bytes")
    lim = _half("c0a0", "c0a3")
    assert _bound("c0a1", "int", lim) in text and _bound("c0a2", "unsigned int", lim) in text, text
    # An index alone (`dest[idx + 0..7]`); the byte value is no index and stays as read.
    text, _ = _case(p, "modbus_set_bits_from_byte")
    assert _bound("c0a1", "int", _half("c0a0")) in text, text
    assert "c0a2 = " not in text, text


def test_an_nb_count_before_its_buffer_is_bounded_by_it():
    """
    `modbus_write_registers(ctx, addr, nb, const uint16_t *src)` and `modbus_read_bits(ctx, addr, nb,
    uint8_t *dest)`: the count comes before the buffer and is named `nb` (`write_nb`, `read_nb`).
    The buffer of such a call is a spare buffer's worth of elements, the count kept within it;
    the register address is no index into the buffer and stays as read.
    """
    for name in ("nb", "nb_bits", "write_nb", "read_nb", "nbItems"):
        assert ah._ARRAY_COUNT_RE.search(name), name
    for name in ("nbytes", "unb", "addr", "value", "tab_byte"):
        assert not ah._ARRAY_COUNT_RE.search(name), name
    p = _plan(MODBUS_RECS)
    text, lay = _case(p, "modbus_write_registers")
    spare = ah.spare_bytes(64)
    assert f"static unsigned short c0a3[({spare} + sizeof(unsigned short) - 1) / sizeof(unsigned short)];" in text, text
    assert _bound("c0a2", "int", _half("c0a3")) in text, text
    assert "c0a1 = " not in text, text
    assert {"call": 0, "param": 3, "size": 2, "kind": "pointee"} in lay["slots"], lay
    text, _ = _case(p, "modbus_read_bits")
    assert _bound("c0a2", "int", _half("c0a3")) in text and "c0a1 = " not in text, text
    text, _ = _case(p, "modbus_write_and_read_registers")
    lim = _half("c0a3", "c0a6")
    assert _bound("c0a2", "int", lim) in text and _bound("c0a5", "int", lim) in text, text
    assert "c0a1 = " not in text and "c0a4 = " not in text, text


def test_an_index_of_a_call_with_a_length_is_left_to_the_callee():
    # A (buffer, length) pair: the callee can check an offset against the length, so the offset
    # stays as read (a missing check is the library's bug, not the harness's).
    recs = {
        "peek": (
            "int(unsigned char *,unsigned long,unsigned long)",
            [("buf", "const_pointer"), ("len", "value"), ("offset", "value")],
        )
    }
    text, _ = _case(_plan(recs), "peek")
    assert "c0a2 = " not in text, text
