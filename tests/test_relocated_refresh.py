"""
After security_props.py moves a wrapper sink's property (`checked_at`, `properties[*].relocated`), the
ledger and the report follow.

libmodbus run-1: twelve callers of `send_msg` were blocked on `L5_sanitized_send_msg` by WP results, and
the wrapper's own unit was keyed on the inner sinks' properties. `ledger.py seed --refresh` re-derives
only units no phase worked on, so those stayed keyed on a property no run generates any more, and
REPORT.md did not say the property had moved.

The security_props.json documents are generated from the recorded wrapper model
(tests/fixtures/security_props/wrapper/, tests/test_security_props_wrapper.py); the WP reports ingested
to give the units their evidence are hand-built in the shape run_wp_function.py writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import generate_report as G
import ledger as L
import security_props as sp
import test_security_props as tsp
import test_security_props_wrapper as tw
from conftest import write_json

pytestmark = pytest.mark.unit

RELOC_DAG = Path("workspace/reports/callgraph_dag.json")
RELOC_PROPS = Path("workspace/reports/security_props.json")
CALLER_TCP = "prog.c#request_tcp::l5_sanitized"
CALLER_RTU = "prog.c#request_rtu::l5_sanitized"
WRAPPER_UNIT = "prog.c#send_frame::l5_sanitized"
DIRECT_CALLER = "prog.c#ping::l5_sanitized"


def _before() -> dict:
    """The property at the callers of `send_frame`, as a run recorded it before the move."""
    sinks = [tw.CHECKED_AT_SINK, tw.TCP_SINK, tw.RTU_SINK]
    return sp.generate(
        tw.wrapper_model(), tsp.threat(output_sinks=sinks), keep_at_callers={"send_frame": "not applied"}
    )


def _unproven_report(function: str, annotation: str) -> dict:
    goal = {"kind": "user assertion", "line": 9, "annotation": annotation, "obligation_class": "l5_sanitized"}
    return {
        "status": "unproven_goals_remain",
        "function": function,
        "file": "workspace/work/prog.c",
        "by_obligation_class": {"l5_sanitized": {"proven": 0, "proven_under_hyp": 0, "unproven": 1}},
        "unproven_goals": [goal],
        "limits": {},
    }


def _run1_state(run: Path) -> dict[str, dict]:
    """Seeded before the move; WP then failed the property at one caller and in the wrapper."""
    tsp._seed_one_file(run, tw.wrapper_model(), _before())
    for function, name in (("request_tcp", "L5_sanitized_send_frame"), ("send_frame", "L5_sanitized_tcp_send")):
        path = run / "workspace/reports/wp" / f"{function}.json"
        write_json(path, _unproven_report(function, f"{name}: meta: \\initialized(msg + (0 .. 11))"))
        L.cmd_ingest_wp([path])
    return tsp._ledger_units(run)


def _refresh(run: Path, doc: dict, refresh: bool = True) -> dict:
    write_json(run / RELOC_PROPS, doc)
    return L.cmd_seed(run / RELOC_DAG, [], "frama_c", refresh=refresh)


def test_the_units_of_a_moved_property_are_retired_or_planned_again(run_dir):
    units = _run1_state(run_dir)
    assert units[CALLER_TCP]["status"] == "blocked" and units[WRAPPER_UNIT]["status"] == "blocked"
    assert units[CALLER_TCP]["bookkeeping"]["security_properties"] == ["L5_sanitized_send_frame"]
    assert units[WRAPPER_UNIT]["bookkeeping"]["security_properties"] == [
        "L5_sanitized_rtu_send",
        "L5_sanitized_tcp_send",
    ]
    result = _refresh(run_dir, tw.wrapper_doc())
    units = tsp._ledger_units(run_dir)
    # The caller WP had worked on: retired, its evidence kept, the reason said. `blocked`, because the
    # ledger refuses an `out_of_scope` unit that carries evidence.
    caller = units[CALLER_TCP]
    assert caller["status"] == "blocked"
    assert caller["unresolved"] == [
        "property_relocated: L5_sanitized_send_frame is checked inside prog.c#send_frame, where it hands the buffer over"
    ]
    assert [e["result"] for e in caller["evidence"]] == ["wp_unproven", "property_relocated"]
    assert caller["evidence"][-1]["discharging"] is False and caller["evidence"][-1]["phase"] == "static"
    assert "security_properties" not in caller.get("bookkeeping", {})
    # The wrapper: planned again on the check that replaced the inner sinks' properties.
    wrapper = units[WRAPPER_UNIT]
    assert wrapper["status"] == "planned" and wrapper["unresolved"] == []
    assert wrapper["bookkeeping"]["security_properties"] == [tw.WRAPPER_PROP]
    assert [e["result"] for e in wrapper["evidence"]] == ["wp_unproven", "property_relocated"]
    assert "L5_sanitized_send_frame, written before the call in prog.c#send_frame" in wrapper["evidence"][-1]["summary"]
    assert result["refresh"]["relocated"] == {
        "retired": [CALLER_TCP],
        "replanned": [WRAPPER_UNIT],
        "kept_candidate": [],
        "count": 2,
    }
    assert not L.validate_ledger(list(units.values()))
    # Controls. The caller no phase worked on is retired by the ordinary refresh; a direct caller of an
    # inner sink keeps its unit and its property.
    assert units[CALLER_RTU]["status"] == "out_of_scope" and units[CALLER_RTU]["unresolved"] == [L.CLASS_NOT_DERIVED]
    assert CALLER_RTU in result["refresh"]["units"]["retired"]
    assert units[DIRECT_CALLER]["status"] == "planned"
    assert units[DIRECT_CALLER]["bookkeeping"]["security_properties"] == ["L5_sanitized_tcp_send"]
    # A second refresh has nothing left to move.
    again = _refresh(run_dir, tw.wrapper_doc())
    assert again["refresh"]["relocated"]["count"] == 0 and tsp._ledger_units(run_dir) == units


def test_without_refresh_and_without_a_move_nothing_is_rewound(run_dir):
    units = _run1_state(run_dir)
    # A plain seed never rewinds a unit, moved property or not.
    result = _refresh(run_dir, tw.wrapper_doc(), refresh=False)
    assert "refresh" not in result and tsp._ledger_units(run_dir) == units
    # A refresh on the report that moved nothing leaves the units WP worked on alone.
    result = _refresh(run_dir, _before())
    assert result["refresh"]["relocated"] == {"retired": [], "replanned": [], "kept_candidate": [], "count": 0}
    assert tsp._ledger_units(run_dir) == units


def test_a_unit_with_an_open_candidate_is_listed_not_moved(run_dir):
    """On the units in memory (a candidate unit on disk needs its candidates.json record)."""
    units = _run1_state(run_dir)
    units[CALLER_TCP]["status"] = "candidate"
    kept = json.loads(json.dumps(units[CALLER_TCP]))
    result = L._refresh_relocated(units, {}, tw.wrapper_doc(), "workspace/reports/security_props.json")
    assert units[CALLER_TCP] == kept
    assert result == {"retired": [WRAPPER_UNIT], "replanned": [], "kept_candidate": [CALLER_TCP], "count": 2}


def test_the_moves_a_report_records():
    assert L.relocated_properties(_before()) == {} and L.relocated_properties(None) == {}
    assert L.relocated_properties({"properties": "x"}) == {}
    moved = L.relocated_properties(tw.wrapper_doc())
    assert sorted(moved) == ["prog.c#request_rtu", "prog.c#request_tcp", "prog.c#send_frame"]
    assert sorted(moved["prog.c#send_frame"]) == ["L5_sanitized_rtu_send", "L5_sanitized_tcp_send"]
    assert sorted(moved["prog.c#request_rtu"]) == ["L5_sanitized_send_frame"]


def test_the_report_says_where_a_moved_property_is_checked(run_dir):
    text = "\n".join(G.security_props_lines(tw.wrapper_doc()))
    assert "### Properties checked somewhere else than at the calls of their sink" in text
    assert (
        "- `L5_sanitized_send_frame`: not generated at the 2 caller(s) of `prog.c#send_frame` "
        "(`prog.c#request_rtu`, `prog.c#request_tcp`); checked inside `prog.c#send_frame` instead"
    ) in text
    assert "Checked before the indirect call `(ctx->backend)->send` at `prog.c:67`, which can dispatch to" in text
    assert "`prog.c#rtu_recv`, `prog.c#rtu_send`, `prog.c#tcp_recv`, `prog.c#tcp_send`" in text
    assert (
        "stands for `L5_sanitized_rtu_send in prog.c#send_frame`, `L5_sanitized_tcp_send in prog.c#send_frame`" in text
    )
    assert "which get no check: `(ctx->backend)->frame_pre at prog.c:66`" in text
    assert "  - Not shown by the model, which records no call arguments: which calls receive the buffer." in text
    assert "still keyed" not in text
    # Control: nothing moved, nothing printed.
    assert "checked somewhere else" not in "\n".join(G.security_props_lines(_before()))
    assert G.security_props_lines(None) == []


def test_the_report_lists_the_units_still_keyed_on_a_moved_property(run_dir):
    units = _run1_state(run_dir)
    stale = "\n".join(G.security_props_lines(tw.wrapper_doc(), list(units.values())))
    assert "**3 ledger unit(s) are still keyed on a property that is no longer generated at their function**" in stale
    assert "`prog.c#request_tcp::l5_sanitized (L5_sanitized_send_frame)`" in stale
    assert "`prog.c#send_frame::l5_sanitized (L5_sanitized_rtu_send, L5_sanitized_tcp_send)`" in stale
    assert "`ledger.py seed --refresh` retires them or plans them again." in stale
    _refresh(run_dir, tw.wrapper_doc())
    fresh = "\n".join(G.security_props_lines(tw.wrapper_doc(), list(tsp._ledger_units(run_dir).values())))
    assert "checked somewhere else" in fresh and "still keyed" not in fresh
    # The retired unit reads `blocked` in the ledger: the report says it is not an open proof.
    assert (
        "- 1 unit(s) had results on a property before it moved and are retired (`prog.c#request_tcp::l5_sanitized`)"
        in fresh
    )
    assert "nothing is left to prove there" in fresh and "retired" not in stale
