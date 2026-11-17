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
    return f"1ULL + ((unsigned long long){var} - 1ULL) % {n}"


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
    text, lay = _case(_plan(RECS), "put")
    assert "int c0a0;" in text and "&c0a0" in text, text
    assert "% " not in text, text
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
