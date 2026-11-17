"""Byte buffers an `--api` case declares are aligned for any object (mpack run-3, S9).

A case backed `node.data` (an `mpack_node_data_t *`) and other typed pointers with a plain
`static unsigned char c0a0f0[4024]`. Nothing in the declaration says the array is aligned, so the
pointer-alignment RTE goal `\\aligned(node.data, 8)` stayed Unknown for Eva although the object is
aligned at run time (two Adversarial Breakers of Phase 3 came back `clean` on it).
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import api_harness as ah

pytestmark = pytest.mark.unit

_BYTE_ARRAY_RE = re.compile(r"(?P<head>[^;{}]*)\bunsigned char (?P<name>\w+)\[")

NODE_LAYOUT: dict[str, Any] = {
    "what": "struct",
    "size": 16,
    "align": 8,
    "pointers": True,
    "fields": [
        {"name": "data", "kind": "ptr", "off": 0, "size": 8, "const": False},
        {"name": "tree", "kind": "ptr", "off": 8, "size": 8, "const": False},
    ],
}
BIG_LAYOUT: dict[str, Any] = {"what": "struct", "size": 64, "align": 32, "pointers": False, "fields": []}


def _plan(recs: dict[str, tuple[str, list[tuple[str, str]]]], traces: list[list[dict]] | None = None) -> dict:
    functions = {n: {"name": n, "file": "lib.c", "is_static": False, "module": "lib"} for n in recs}
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": list(recs), "functions": list(recs)}},
        "functions": functions,
    }
    model = {
        "status": "ok",
        "functions": {
            f"lib.c#{n}": {"name": n, "signature": sig, "formals": [{"name": a, "kind": k} for a, k in formals]}
            for n, (sig, formals) in recs.items()
        },
    }
    layouts = {"struct node": NODE_LAYOUT, "struct big": BIG_LAYOUT}
    return ah.plan(dag, model, "lib", "lib", 64, traces, None, layouts, ah.Declared(set(recs), {}))


RECS = {
    # A struct by value whose pointer fields get shadow buffers (mpack_node_t's data and tree).
    "node_bool": ("int(struct node)", [("node", "value")]),
    # A (buffer, length) pair the call writes, and a byte buffer of no known size.
    "fill": ("int(char *,unsigned long,char *)", [("out", "pointer"), ("n", "value"), ("scratch", "pointer")]),
}


def _byte_arrays(cases: list[str]) -> list[tuple[str, str]]:
    return [(m.group("name"), m.group("head")) for c in cases for m in _BYTE_ARRAY_RE.finditer(c)]


def test_every_byte_buffer_of_a_case_is_aligned():
    p = _plan(RECS)
    arrays = _byte_arrays(p["cases"])
    assert {name for name, _ in arrays} >= {"c0a0f0", "c0a0f1", "c0a0", "c0a2"}, arrays
    for name, head in arrays:
        # 16: the strictest alignment of a scalar on x86_64 (`max_align_t`, which C99 headers lack).
        assert "_Alignas(16)" in head, (name, head)


def test_a_shared_struct_buffer_is_aligned():
    # A sequence case shares one object between calls through a byte array sized for the struct. It
    # is aligned like any other buffer, also for a struct whose layout says more: Frama-C refuses
    # `_Alignas` above alignof(max_align_t) (16).
    recs = {
        "big_init": ("void(struct big *)", [("b", "pointer")]),
        "big_use": ("int(struct big *)", [("b", "pointer")]),
    }
    trace = [{"fn": "big_init", "addrs": {"0": "0x10"}}, {"fn": "big_use", "addrs": {"0": "0x10"}}]
    p = _plan(recs, [trace])
    seq = [c for c, lay in zip(p["cases"], p["layouts"], strict=True) if lay["kind"] == "sequence"]
    assert seq, p["layouts"]
    heads = [head for _, head in _byte_arrays(seq)]
    assert heads and all("_Alignas(16)" in h for h in heads), heads


def test_the_alignment_changes_no_layout():
    # Only declarations change: the slots, rest and selectors (and the seeds they drive) stay.
    p = _plan(RECS)
    lay = p["layouts"][[x.get("entry") for x in p["layouts"]].index("fill")]
    assert lay["slots"] == [{"call": 0, "param": 1, "size": 8, "kind": "int"}]
    assert lay["rest"] is None
