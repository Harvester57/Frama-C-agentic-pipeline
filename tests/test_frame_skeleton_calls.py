"""Frame skeleton and calls: `assigns \\nothing` only for a function that cannot write through a call
(frame_skeleton.compute with the module verdict from function_facts.build_module_facts)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import frame_skeleton as fs  # noqa: E402
import function_facts as ff  # noqa: E402
import kernel_ast  # noqa: E402

NOTHING = "assigns \\nothing;"


def _clauses(skel: dict) -> list[str]:
    return [a["clause"] for a in skel.get("assigns") or []]


# ---------------------------------------------------------------------------
# frame_skeleton.compute on one record
# ---------------------------------------------------------------------------


def _rec(**kw) -> dict:
    rec: dict = {"formals": [], "writes": [], "reads": [], "loops": [], "may_alias": [], "return_paths": []}
    rec.update(kw)
    return rec


def _call(callee: str, indirect: bool = False) -> dict:
    if indirect:
        return {"line": 3, "indirect": True, "in_loop": False, "args": [], "expr": "*fp"}
    return {"line": 3, "indirect": False, "in_loop": False, "args": ["p"], "callee": callee, "kernel_name": callee}


def test_leaf_without_writes_or_calls_keeps_assigns_nothing() -> None:
    skel = fs.compute(_rec(), write_free_callees=set())
    assert skel["status"] == "ok"
    assert _clauses(skel) == [NOTHING]


def test_call_to_a_writing_callee_gives_no_assigns_nothing_and_a_partial_skeleton() -> None:
    skel = fs.compute(_rec(calls=[_call("append")]), write_free_callees=set())
    assert skel["assigns"] == []
    assert skel["status"] == "partial"
    assert any("`append`" in n for n in skel["notes"])


def test_call_to_a_write_free_callee_keeps_assigns_nothing() -> None:
    skel = fs.compute(_rec(calls=[_call("pure")]), write_free_callees={"pure"})
    assert skel["status"] == "ok"
    assert _clauses(skel) == [NOTHING]


def test_indirect_call_blocks_assigns_nothing() -> None:
    skel = fs.compute(_rec(calls=[_call("", indirect=True)]), write_free_callees={"pure"})
    assert skel["assigns"] == [] and skel["status"] == "partial"
    assert any("indirect" in n for n in skel["notes"])


def test_without_a_module_verdict_any_call_blocks_assigns_nothing() -> None:
    skel = fs.compute(_rec(calls=[_call("pure")]))
    assert NOTHING not in _clauses(skel)
    assert skel["status"] == "partial"


def test_a_write_through_a_local_pointer_blocks_assigns_nothing() -> None:
    write = {"lval": "*q", "root": "q", "root_kind": "local", "through_pointer": True, "line": 4}
    skel = fs.compute(_rec(writes=[write]), write_free_callees=set())
    assert NOTHING not in _clauses(skel)
    assert skel["status"] == "partial"
    assert not fs.writes_nothing_directly(_rec(writes=[write]))


def test_a_truncated_record_does_not_claim_assigns_nothing() -> None:
    skel = fs.compute(_rec(truncated=True), write_free_callees=set())
    assert NOTHING not in _clauses(skel)
    assert skel["status"] == "partial"


def test_direct_writes_are_still_projected_when_a_callee_writes() -> None:
    write = {"lval": "*out", "root": "out", "root_kind": "formal", "through_pointer": True, "line": 4}
    skel = fs.compute(_rec(writes=[write], calls=[_call("append")]), write_free_callees=set())
    assert _clauses(skel) == ["assigns *out \\from \\nothing;"]


# ---------------------------------------------------------------------------
# The module pass in function_facts.build_module_facts
# ---------------------------------------------------------------------------


def _raw_call(callee: str, loc: str, indirect: bool = False) -> dict:
    return {
        "callee": callee,
        "kernel_name": callee,
        "indirect": indirect,
        "expr": "*fp" if indirect else None,
        "args": ["pMe"],
        "arg_shapes": [],
        "conditions": [],
        "conditions_partial": False,
        "loc": loc,
        "in_loop": False,
    }


def _raw(name: str, loc: str, writes=(), calls=()) -> dict:
    return {
        "kernel_name": name,
        "name": name,
        "loc": loc,
        "static": False,
        "variadic": False,
        "return_type": "void",
        "formals": [{"name": "pMe", "type": "t *", "kind": "pointer", "restrict": False, "pointee": "t"}],
        "loops": [],
        "calls": list(calls),
        "writes": list(writes),
        "reads": [],
        "return_paths": [],
        "derived_pointers": [],
        "truncated": False,
        "features": {},
    }


def _pme_write() -> dict:
    return {"lval": "pMe->len", "base": "pMe", "base_kind": "formal", "through_pointer": True, "values": ["0"]}


def _fake_run(ast_doc: dict) -> Any:
    def run(cmd, **kwargs):
        if cmd[0] == "ocamlfind":
            (Path(kwargs["cwd"]) / cmd[cmd.index("-o") + 1]).write_bytes(b"cmxs")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "frama-c":
            Path(kwargs["env"][kernel_ast.OUT_ENV]).write_text(json.dumps(ast_doc), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] in ("gcc", "clang"):
            return subprocess.CompletedProcess(cmd, 0, f"x.o: {cmd[-1]}\n", "")
        raise AssertionError(cmd)

    return run


def _facts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, functions: list[dict]) -> dict:
    monkeypatch.chdir(tmp_path)
    Path("m.c").write_text("\n" * 60, encoding="utf-8")
    doc = ff.build_module_facts("m", ["m.c"], "-I.", None, runner=_fake_run({"functions": functions}))
    return {key.split("#", 1)[1]: rec["frame_skeleton"] for key, rec in doc["functions"].items()}


def test_forwarder_to_a_writing_callee_is_not_projected_as_assigns_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skel = _facts(
        tmp_path,
        monkeypatch,
        [
            _raw("AppendUsefulBuf", "m.c:1", writes=[_pme_write()]),
            _raw("AppendData", "m.c:10", calls=[_raw_call("AppendUsefulBuf", "m.c:11")]),
        ],
    )
    assert _clauses(skel["AppendUsefulBuf"]) == ["assigns pMe->len \\from \\nothing;"]
    assert skel["AppendData"]["assigns"] == []
    assert skel["AppendData"]["status"] == "partial"
    assert any("AppendUsefulBuf" in n for n in skel["AppendData"]["notes"])


def test_writes_through_a_chain_of_forwarders_are_seen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skel = _facts(
        tmp_path,
        monkeypatch,
        [
            _raw("writer", "m.c:1", writes=[_pme_write()]),
            _raw("mid", "m.c:10", calls=[_raw_call("writer", "m.c:11")]),
            _raw("top", "m.c:20", calls=[_raw_call("mid", "m.c:21")]),
        ],
    )
    assert skel["mid"]["assigns"] == [] and skel["top"]["assigns"] == []
    assert any("`mid`" in n for n in skel["top"]["notes"])


def test_caller_of_only_write_free_module_callees_keeps_assigns_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skel = _facts(
        tmp_path,
        monkeypatch,
        [
            _raw("leaf", "m.c:1"),
            _raw("mid", "m.c:10", calls=[_raw_call("leaf", "m.c:11")]),
            _raw("top", "m.c:20", calls=[_raw_call("mid", "m.c:21"), _raw_call("leaf", "m.c:22")]),
        ],
    )
    for name in ("leaf", "mid", "top"):
        assert _clauses(skel[name]) == [NOTHING], name
        assert skel[name]["status"] == "ok", name


def test_external_and_indirect_callees_block_assigns_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skel = _facts(
        tmp_path,
        monkeypatch,
        [
            _raw("copies", "m.c:1", calls=[_raw_call("memcpy", "m.c:2")]),
            _raw("dispatches", "m.c:10", calls=[_raw_call("", "m.c:11", indirect=True)]),
            _raw("harnessed", "m.c:20", calls=[_raw_call("eva_main", "m.c:21")]),
            _raw("eva_main", "workspace/harnesses/harness_m.c:3"),
        ],
    )
    for name in ("copies", "dispatches", "harnessed"):
        assert skel[name]["assigns"] == [] and skel[name]["status"] == "partial", name
    assert any("memcpy" in n and "outside" in n for n in skel["copies"]["notes"])


def test_recursion_is_write_free_only_when_every_member_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skel = _facts(
        tmp_path,
        monkeypatch,
        [
            # A write-free cycle: even <-> odd, and a self-recursive walk.
            _raw("even", "m.c:1", calls=[_raw_call("odd", "m.c:2")]),
            _raw("odd", "m.c:5", calls=[_raw_call("even", "m.c:6")]),
            _raw("walk", "m.c:8", calls=[_raw_call("walk", "m.c:9")]),
            # A cycle with one writing member: every member, and its caller, may write.
            _raw("ping", "m.c:20", calls=[_raw_call("pong", "m.c:21")]),
            _raw("pong", "m.c:25", writes=[_pme_write()], calls=[_raw_call("ping", "m.c:26")]),
            _raw("user", "m.c:30", calls=[_raw_call("ping", "m.c:31")]),
            _raw("pure_user", "m.c:40", calls=[_raw_call("even", "m.c:41")]),
        ],
    )
    for name in ("even", "odd", "walk", "pure_user"):
        assert _clauses(skel[name]) == [NOTHING], name
    for name in ("ping", "user"):
        assert skel[name]["assigns"] == [] and skel[name]["status"] == "partial", name
    assert _clauses(skel["pong"]) == ["assigns pMe->len \\from \\nothing;"]


def test_same_named_statics_are_resolved_by_kernel_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("a.c").write_text("\n" * 30, encoding="utf-8")
    Path("b.c").write_text("\n" * 30, encoding="utf-8")
    writer = _raw("helper", "b.c:1", writes=[_pme_write()])
    writer["kernel_name"] = "helper_0"
    call_b = {**_raw_call("helper", "b.c:11"), "kernel_name": "helper_0"}
    functions = [
        _raw("helper", "a.c:1"),
        writer,
        _raw("use_a", "a.c:10", calls=[_raw_call("helper", "a.c:11")]),
        _raw("use_b", "b.c:10", calls=[call_b]),
    ]
    doc = ff.build_module_facts("m", ["a.c", "b.c"], "-I.", None, runner=_fake_run({"functions": functions}))
    fns = doc["functions"]
    assert _clauses(fns["a.c#use_a"]["frame_skeleton"]) == [NOTHING]
    assert fns["b.c#use_b"]["frame_skeleton"]["assigns"] == []


# ---------------------------------------------------------------------------
# The brief
# ---------------------------------------------------------------------------


def test_brief_states_no_required_clause_for_a_partial_skeleton_without_clauses() -> None:
    record = {
        "name": "AppendData",
        "frame_skeleton": {
            "status": "partial",
            "separated": [],
            "assigns": [],
            "notes": ["no `assigns \\nothing` projected: calls `AppendUsefulBuf`, which may write"],
        },
    }
    lines: list[str] = []
    ff._render_skeleton(record, lines)
    text = "\n".join(lines)
    assert "REQUIRED minimum" not in text
    assert "AppendUsefulBuf" in text
    assert "`assigns \\nothing;`" not in text


def test_facts_schema_changes_with_the_rule() -> None:
    # Facts cached or written under the old rule (schema 3) must not be reused.
    assert ff.FACTS_SCHEMA >= 4
