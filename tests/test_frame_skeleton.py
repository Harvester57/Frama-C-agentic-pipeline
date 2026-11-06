"""Frame skeleton projection (scripts/frame_skeleton.py): AutoFraming-style deterministic
`\\separated` / `assigns ... \\from ...` clauses computed from function facts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import frame_skeleton as fs  # noqa: E402


def _formal(name, kind="scalar", pointee=None, char_like=False, restrict=False):
    out = {"name": name, "type": "t", "kind": kind, "restrict": restrict}
    if pointee:
        out.update(pointee=pointee, pointee_canon=pointee, char_like=char_like)
    return out


def _access(lval, root, kind="formal", pointer=True):
    return {"lval": lval, "root": root, "root_kind": kind, "through_pointer": pointer, "line": 9}


def _record(**kw):
    rec = {
        "formals": [],
        "writes": [],
        "reads": [],
        "loops": [],
        "may_alias": [],
        "return_paths": [],
        "eva": {"status": "unavailable"},
        "truncated": False,
    }
    rec.update(kw)
    return rec


def _parse_value_record():
    """The paper's motivating example: parse_value(buf, len, eaten)."""
    return _record(
        formals=[
            _formal("buf", "pointer", "uint16_t"),
            _formal("len"),
            _formal("eaten", "pointer", "uint16_t"),
        ],
        writes=[_access("*eaten", "eaten")],
        reads=[_access("*(buf + 0)", "buf"), _access("*(buf + 1)", "buf")],
        may_alias=[{"a": "buf", "b": "eaten", "written": ["eaten"], "reason": "same pointee type"}],
        return_paths=[
            {"value": "-1", "conditions": ["len < 2", "buf == (uint16_t *)0", "eaten == (uint16_t *)0"]},
            {"value": "0", "conditions": []},
        ],
    )


def test_parse_value_projects_separation_and_from_footprint() -> None:
    skel = fs.compute(_parse_value_record())
    assert skel["status"] == "ok"
    assert len(skel["separated"]) == 1
    sep = skel["separated"][0]
    assert sep["roots"] == ["buf", "eaten"]
    assert sep["clause"] == "requires \\separated(buf + (0 .. 1), eaten);"
    assert len(skel["assigns"]) == 1
    a = skel["assigns"][0]
    assert a["loc"] == "*eaten"
    assert a["from"] == ["buf + (0 .. 1)", "len"]
    assert a["clause"] == "assigns *eaten \\from buf + (0 .. 1), len;"


def _copy_loop_record():
    loop = {
        "index": 0,
        "parent": None,
        "line": 4,
        "guard": "i < n",
        "scalars": [{"var": "i", "updates": ["i + 1"]}],
        "memory_writes": [{"lval": "*(dst + i)", "root": "dst", "root_kind": "formal", "values": ["*(src + i)"]}],
        "reads": [{"lval": "*(src + i)", "root": "src", "root_kind": "formal"}],
        "calls": [],
        "exits": [],
    }
    return _record(
        formals=[
            _formal("dst", "pointer", "char", char_like=True),
            _formal("src", "pointer", "char", char_like=True),
            _formal("n"),
        ],
        loops=[loop],
        writes=[_access("*(dst + i)", "dst"), _access("g", "g", "global", pointer=False)],
        reads=[_access("*(src + i)", "src")],
        may_alias=[{"a": "dst", "b": "src", "written": ["dst"], "reason": "same pointee type"}],
    )


def test_copy_loop_normalizes_loop_write_to_range_and_lifts_read_to_region() -> None:
    skel = fs.compute(_copy_loop_record())
    assert skel["status"] == "ok"
    assert [s["clause"] for s in skel["separated"]] == ["requires \\separated(dst + (0 .. n - 1), src + (0 .. n - 1));"]
    by_loc = {a["loc"]: a for a in skel["assigns"]}
    assert by_loc["dst + (0 .. n - 1)"]["from"] == ["n", "src + (0 .. n - 1)"]
    assert by_loc["dst + (0 .. n - 1)"]["clause"] == ("assigns dst + (0 .. n - 1) \\from n, src + (0 .. n - 1);")
    # The global write has no AST value flow: sound superset of the read roots.
    assert by_loc["g"]["source"] == "ast-superset"
    assert by_loc["g"]["from"] == ["n", "src + (0 .. n - 1)"]


def test_no_separation_when_the_other_pointer_is_never_read() -> None:
    rec = _record(
        formals=[_formal("out", "pointer", "int"), _formal("in", "pointer", "int")],
        writes=[_access("*out", "out")],
        reads=[],
        may_alias=[{"a": "in", "b": "out", "written": ["out"], "reason": "same pointee type"}],
    )
    skel = fs.compute(rec)
    assert skel["separated"] == []
    assert [a["clause"] for a in skel["assigns"]] == ["assigns *out \\from \\nothing;"]


def test_no_may_alias_pairs_means_no_separation() -> None:
    # restrict pointers and incompatible pointees never reach may_alias (that filter lives
    # in function_facts._may_alias, tested there); compute trusts may_alias as given.
    rec = _record(
        formals=[
            _formal("a", "pointer", "int", restrict=True),
            _formal("b", "pointer", "int"),
            _formal("d", "pointer", "double"),
        ],
        writes=[_access("*a", "a")],
        reads=[_access("*b", "b")],
        may_alias=[],
    )
    assert fs.compute(rec)["separated"] == []


def test_pure_function_projects_assigns_nothing() -> None:
    rec = _record(formals=[_formal("a"), _formal("b")], reads=[_access("a", "a", pointer=False)])
    skel = fs.compute(rec)
    assert skel["assigns"] == [{"loc": "\\nothing", "from": [], "clause": "assigns \\nothing;", "source": "ast"}]
    assert skel["separated"] == []


def test_inclusive_guard_gives_inclusive_range() -> None:
    loop = {
        "index": 0,
        "guard": "i <= n",
        "scalars": [{"var": "i", "updates": ["i + 1"]}],
        "memory_writes": [{"lval": "*(a + i)", "root": "a", "root_kind": "formal", "values": ["0"]}],
        "reads": [],
    }
    rec = _record(
        formals=[_formal("a", "pointer", "int"), _formal("n")],
        loops=[loop],
        writes=[_access("*(a + i)", "a")],
    )
    skel = fs.compute(rec)
    assert skel["assigns"][0]["loc"] == "a + (0 .. n)"


def test_non_entry_expressible_index_is_kept_and_marked_partial() -> None:
    loop = {
        "index": 0,
        "guard": "i < n",
        "scalars": [{"var": "i", "updates": ["i + 1"]}],
        "memory_writes": [{"lval": "*(a + 2 * i)", "root": "a", "root_kind": "formal", "values": ["0"]}],
        "reads": [],
    }
    rec = _record(
        formals=[_formal("a", "pointer", "int"), _formal("n")],
        loops=[loop],
        writes=[_access("*(a + 2 * i)", "a")],
    )
    skel = fs.compute(rec)
    assert skel["status"] == "partial"
    assert skel["assigns"][0]["loc"] == "*(a + 2 * i)"
    assert any("non-entry-expressible" in n for n in skel["notes"])


def test_straight_line_write_with_rhs_values_gets_a_precise_from() -> None:
    # The dump now carries RHS expressions for straight-line writes too: the footprint is
    # the RHS roots + control roots, NOT the superset of every read root (`other` is read
    # but does not flow into the write).
    rec = _record(
        formals=[
            _formal("buf", "pointer", "uint16_t"),
            _formal("other", "pointer", "uint16_t"),
            _formal("len"),
            _formal("eaten", "pointer", "uint16_t"),
        ],
        writes=[{**_access("*eaten", "eaten"), "values": ["*(buf + 0) + *(buf + 1)"]}],
        reads=[_access("*(buf + 0)", "buf"), _access("*(buf + 1)", "buf"), _access("*other", "other")],
        may_alias=[{"a": "buf", "b": "eaten", "written": ["eaten"], "reason": "same pointee type"}],
        return_paths=[{"value": "-1", "conditions": ["len < 2"]}, {"value": "0", "conditions": []}],
    )
    skel = fs.compute(rec)
    a = skel["assigns"][0]
    assert a["loc"] == "*eaten"
    assert a["source"] == "ast"
    assert a["from"] == ["buf + (0 .. 1)", "len"]
    assert not any("other" in f for f in a["from"])


def test_kill_switch_disables_the_skeleton(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRAMAC_FRAME_SKELETON", "off")
    assert fs.compute(_parse_value_record()) == {"status": "disabled"}
    monkeypatch.delenv("FRAMAC_FRAME_SKELETON")
    assert fs.compute(_parse_value_record())["status"] == "ok"


def test_compute_never_raises_on_garbage() -> None:
    assert fs.compute({})["status"] == "ok"
    assert fs.compute({"formals": [{"name": "x"}], "writes": [{"root": None}]})["status"] in ("ok", "partial")
