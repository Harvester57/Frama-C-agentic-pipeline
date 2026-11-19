"""
Package H of docs/plans/metacsl-exploitation-plan.md:

1. a model that does not say which calls are initializers fails closed: the ledger refuses the
   no-goal credit (`wp_meta_simplified`) of the properties MetAcsl skips at such a call;
2. `ingest-eva` withdraws a no-goal credit when a later Eva report leaves a check of the unit open;
3. REPORT.md shows what the MetAcsl work left unchecked;
4. the skill texts and the guide name what the ledger refuses.

The ledger tests reuse the helpers of tests/test_metacsl_classes.py (a seeded one-file run).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import generate_report as gr
import ledger as L
import security_props as sp
from conftest import ROOT, write_json
from test_metacsl_classes import (
    NK_CALL,
    NK_GOALS,
    NK_INVARIANT,
    NK_MODULE,
    NK_READERS,
    NK_SANITIZED,
    NK_WRITERS,
    _eva_section,
    cid,
    new_kinds_doc,
    seed,
    set_unit,
    units,
    wp_report,
)
from test_metacsl_followups import ENGINE_OFF_REPORT_SHA256
from test_report import build_run
from test_security_props import INIT_GATE, INIT_LISTS, INIT_STRONG, _init_model, threat
from workspace_overlay import baseline_wp_report_rel

pytestmark = pytest.mark.unit

BAR_INITIALIZERS = "wp_meta_initializers_unknown"
WITHDRAWN = "eva_no_goal_credit_withdrawn"
RC_ASSET = {"name": "state", "lvalue": "auth_ok", "writers": ["login"], "readers": ["login"], "description": "d"}
RC_EVA_REPORT = f"workspace/reports/eva/{NK_MODULE}.json"
RC_ROW = {"file": "prog.c", "line": 12, "function": "flush", "kind": "user check", "annotation": "ready != 0"}

HEAD_ITEMS = "### Threat-model items without a property"
HEAD_WARNED = "### Properties generated with a warning"
HEAD_DECLARED_WARNINGS = "### Properties that do not see what declared functions write"
HEAD_UNCHECKED = "### Where a property does not check its function"
HEAD_CALLEES = "### Declared functions the write-checking properties call"
HEAD_BARRED = "### Units the ledger refused a credit"
HEAD_WP_RUNS = "### WP runs MetAcsl stopped or left unnamed"
INIT_BLOCK = "> MetAcsl initializer calls: NOT CHECKED"


def flags(doc: dict, known: bool | None, properties: list[str] | None = None) -> dict:
    """`doc` with its `initializer_flags` (None: a document written before the field existed)."""
    doc.pop("initializer_flags", None)
    if known is True:
        doc["initializer_flags"] = {"known": True}
    elif known is False:
        doc["initializer_flags"] = {"known": False, "properties": properties or []}
    return doc


def flagless(model: dict) -> dict:
    for rec in model["functions"].values():
        for site in rec.get("call_sites", []):
            del site["initializer"]
    return model


def full_threat() -> dict:
    return threat(**INIT_LISTS, auth_gates=[INIT_GATE], invariants=[INIT_STRONG], assets=[RC_ASSET])


def eva_ingest(counts: dict[str, dict[str, int]] | None = None, **fields) -> dict:
    report: dict = {"status": "ok", "module": NK_MODULE, "reduced_checks": [], **fields}
    if counts is not None:
        report["security_props"] = _eva_section(counts)
    write_json(Path(RC_EVA_REPORT), report)
    return L.cmd_ingest_eva([Path(RC_EVA_REPORT)])


def results(unit: dict) -> list[str]:
    return [e["result"] for e in unit["evidence"]]


def credited_flush(run: Path) -> None:
    """flush is covered by the no-goal credit: MetAcsl left no goal of its call rule."""
    seed(run, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified"


# ---------------------------------------------------------------------------------------------------
# Item 1: the generator says whether the model marks initializer calls
# ---------------------------------------------------------------------------------------------------


def test_a_model_with_flags_is_recorded_as_known():
    doc = sp.generate(_init_model(), full_threat())
    assert doc["initializer_flags"] == {"known": True} and not sp.validate(doc)


def test_a_model_without_flags_names_the_properties_whose_context_metacsl_skips():
    doc = sp.generate(flagless(_init_model()), full_threat())
    names = {p["name"] for p in doc["properties"]}
    # Skipped at an initializer call: \calling, \writing (from the callee's assigns), \strong_invariant.
    skipped = {"L3_writers_state", "L4_auth_state_login", "L4_invariant_auth_range", "L5_sanitized_net_send"}
    skipped.add("L6_no_leak_key")  # its \reading half is fine, its \calling half is not
    # Handled there: \reading and \precond.
    handled = {"L3_readers_state", "L4_auth_required_login"}
    assert skipped | handled <= names
    assert doc["initializer_flags"]["known"] is False
    assert set(doc["initializer_flags"]["properties"]) == skipped
    assert doc["initializer_flags"]["properties"] == sorted(skipped)
    assert not sp.validate(doc)


def test_one_call_site_without_the_flag_makes_the_model_unknown():
    model = _init_model()
    del model["functions"]["prog.c#f_init"]["call_sites"][0]["initializer"]
    doc = sp.generate(model, full_threat())
    assert doc["initializer_flags"]["known"] is False
    assert [w for w in doc["warnings"] if "do not say which calls are initializers" in w]


def test_a_model_without_call_sites_cannot_tell_and_one_without_calls_has_nothing_to_hide():
    model = _init_model()
    for rec in model["functions"].values():
        rec.pop("call_sites", None)
    assert sp.generate(model, full_threat())["initializer_flags"]["known"] is False
    for rec in model["functions"].values():
        rec["call_sites"] = []
    assert sp.generate(model, full_threat())["initializer_flags"] == {"known": True}


# ---------------------------------------------------------------------------------------------------
# Item 1: the ledger refuses the no-goal credit
# ---------------------------------------------------------------------------------------------------


def test_no_flags_refuse_the_no_goal_credit_of_a_skipped_context(run_dir):
    seed(run_dir, flags(new_kinds_doc(), False, [NK_CALL]))
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    last = unit["evidence"][-1]
    assert unit["status"] == "planned" and last["result"] == BAR_INITIALIZERS and not last["discharging"]
    assert NK_CALL in last["summary"] and "initializer" in last["summary"]
    # The function's other units are not concerned.
    assert units()["prog.c#flush::rte"]["status"] == "covered"
    assert not L.validate_ledger(list(units().values()))


def test_no_flags_leave_a_property_metacsl_handles_at_initializers_alone(run_dir):
    """A readers property: \\reading gets its instance at `int x = key[0];`, so the credit stands."""
    doc = flags(new_kinds_doc(), False, [NK_WRITERS, NK_CALL])
    doc["obligations"]["prog.c#store"] = [o for o in doc["obligations"]["prog.c#store"] if o["property"] != NK_WRITERS]
    seed(run_dir, doc)
    L.cmd_ingest_wp([wp_report("store", {}, loaded=[NK_READERS])])
    unit = units()[cid("store")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified"


def test_one_skipped_property_of_a_unit_is_enough_to_refuse_it(run_dir):
    seed(run_dir, flags(new_kinds_doc(), False, [NK_WRITERS]))
    L.cmd_ingest_wp([wp_report("store", {}, loaded=[NK_READERS, NK_WRITERS])])
    unit = units()[cid("store")]
    assert unit["evidence"][-1]["result"] == BAR_INITIALIZERS
    why = L._meta_initializers_unknown(unit, L._meta_facts())
    assert why is not None and NK_WRITERS in why and NK_READERS not in why


def test_no_flags_do_not_touch_a_proven_goal(run_dir):
    seed(run_dir, flags(new_kinds_doc(), False, [NK_CALL]))
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_proven"


def test_a_document_older_than_the_field_refuses_the_credit_until_it_is_regenerated(run_dir):
    """Unknown fails closed, whatever the context, and the evidence says how to get out of it."""
    seed(run_dir, flags(new_kinds_doc(), None))
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    last = unit["evidence"][-1]
    assert unit["status"] == "planned" and last["result"] == BAR_INITIALIZERS
    assert "security_props.py run" in last["summary"]
    assert L._meta_no_goal_credit_barred(unit, L._meta_facts())
    # Regenerated from a model with flags: the same report credits the unit.
    write_json(Path("workspace/reports/security_props.json"), flags(new_kinds_doc(), True))
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    assert units()[cid("flush")]["evidence"][-1]["result"] == "wp_meta_simplified"


def test_the_flags_are_no_gap_of_the_unit_for_eva_or_for_a_proof(run_dir):
    """A separate fact: it does not reach _meta_unchecked, which would refuse every credit."""
    seed(run_dir, flags(new_kinds_doc(), False, [NK_CALL]))
    facts = L._meta_facts()
    assert L._meta_unchecked(units()[cid("flush")], facts) == []
    assert not L._eva_meta_cover_barred(units()[cid("flush")], facts)


def test_every_earlier_bar_keeps_its_own_evidence(run_dir):
    """An open Eva check says more than the missing flags: the unit keeps the reason it had."""
    seed(run_dir, flags(new_kinds_doc(), False, [NK_CALL]))
    set_unit(cid("flush"), bookkeeping={"eva_verdicts": {NK_MODULE: "unknown"}})
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    assert units()[cid("flush")]["evidence"][-1]["result"] == "wp_meta_simplified_eva_open"


# ---------------------------------------------------------------------------------------------------
# Item 2: ingest-eva withdraws a stale no-goal credit
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("bucket", ["unknown", "other"])
def test_a_later_open_eva_check_withdraws_the_no_goal_credit(run_dir, bucket):
    credited_flush(run_dir)
    stats = eva_ingest({f"{NK_CALL}@flush": {"valid": 1, bucket: 1}})
    unit = units()[cid("flush")]
    assert unit["status"] == "planned" and unit["agent_id"] is None and unit["unresolved"] == []
    last = unit["evidence"][-1]
    assert last["result"] == WITHDRAWN and last["phase"] == "eva" and not last["discharging"]
    assert f"'{NK_MODULE}'" in last["summary"] and last["tool_output"] == RC_EVA_REPORT
    assert not L._wp_discharged(unit) and stats["reopened"] == 1
    assert not L.validate_ledger(list(units().values()))


def test_an_invalid_eva_check_leaves_no_credit_for_a_rejected_candidate_to_fall_back_on(run_dir):
    """A rejected candidate goes back to `covered` when discharging evidence is left on the unit."""
    credited_flush(run_dir)
    eva_ingest({f"{NK_CALL}@flush": {"invalid": 1}})
    unit = units()[cid("flush")]
    assert unit["status"] == "candidate" and WITHDRAWN in results(unit)
    assert not any(e.get("discharging") for e in unit["evidence"])


@pytest.mark.parametrize("bucket", ["dead", "valid"])
def test_a_verdict_that_does_not_block_keeps_the_credit(run_dir, bucket):
    credited_flush(run_dir)
    eva_ingest({f"{NK_CALL}@flush": {bucket: 1}})
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and WITHDRAWN not in results(unit)


def test_no_check_generated_keeps_the_credit(run_dir):
    credited_flush(run_dir)
    eva_ingest({f"{NK_CALL}@flush": {}})
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and WITHDRAWN not in results(unit)


def test_a_cover_backed_by_a_proven_goal_is_not_withdrawn(run_dir):
    seed(run_dir, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and WITHDRAWN not in results(unit)
    assert L._wp_discharged(unit)


def test_a_proof_that_followed_the_no_goal_credit_stands(run_dir):
    credited_flush(run_dir)
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    assert units()[cid("flush")]["status"] == "covered"


def test_a_no_goal_credit_that_followed_a_proof_is_what_the_cover_rests_on(run_dir):
    seed(run_dir, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    unit = units()[cid("flush")]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == WITHDRAWN


def test_a_carried_forward_no_goal_credit_is_withdrawn_like_any_other(run_dir):
    """cmd_mark_carried renames the evidence: the credit it came from must still be recognised."""
    credited_flush(run_dir)
    L.cmd_mark_carried(Path("workspace/reports/wp/flush.json"), "cache/entry", "k1")
    assert units()[cid("flush")]["evidence"][-1]["result"] == "carried_forward_reproven"
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    unit = units()[cid("flush")]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == WITHDRAWN


def test_a_carried_forward_proof_stands(run_dir):
    seed(run_dir, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    L.cmd_mark_carried(Path("workspace/reports/wp/flush.json"), "cache/entry", "k1")
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    assert units()[cid("flush")]["status"] == "covered"


def test_an_open_in_code_check_withdraws_the_credit_without_a_meta_instance(run_dir):
    """The check was placed after the credit, and this Eva run did not load the properties."""
    credited_flush(run_dir)
    doc = new_kinds_doc()
    doc["code_checks"] = [{"file": "prog.c", "line": 12, "function": "prog.c#flush", "property": NK_CALL, "index": 0}]
    write_json(Path("workspace/reports/security_props.json"), doc)
    eva_ingest(unknown_obligations_by_function={"flush": [RC_ROW]})
    unit = units()[cid("flush")]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == WITHDRAWN


def test_the_verdict_of_an_open_in_code_check_ends_with_the_modules_next_report(run_dir):
    credited_flush(run_dir)
    doc = new_kinds_doc()
    doc["code_checks"] = [{"file": "prog.c", "line": 12, "function": "prog.c#flush", "property": NK_CALL, "index": 0}]
    write_json(Path("workspace/reports/security_props.json"), doc)
    eva_ingest(unknown_obligations_by_function={"flush": [RC_ROW]})
    assert units()[cid("flush")]["bookkeeping"]["eva_verdicts"] == {NK_MODULE: "unknown"}
    eva_ingest()
    assert not units()[cid("flush")]["bookkeeping"]["eva_verdicts"]
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    assert units()[cid("flush")]["evidence"][-1]["result"] == "wp_meta_check_not_reported"


def test_after_a_withdrawal_eva_or_the_same_wp_report_can_close_the_unit_again(run_dir):
    credited_flush(run_dir)
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    # Still open: the same WP report gets the refusal, not the credit.
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == "wp_meta_simplified_eva_open"
    # The module's next report proves the check: Eva covers the unit.
    eva_ingest({f"{NK_CALL}@flush": {"valid": 1}})
    assert units()[cid("flush")]["status"] == "covered"
    # And without a verdict that blocks, the WP report credits it again.
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified"
    assert unit["evidence"][-1]["discharging"] and not L.validate_ledger(list(units().values()))


def test_withdrawing_twice_adds_nothing(run_dir):
    credited_flush(run_dir)
    eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    before = results(units()[cid("flush")])
    stats = eva_ingest({f"{NK_CALL}@flush": {"unknown": 1}})
    assert results(units()[cid("flush")]) == before and "reopened" not in stats


# ---------------------------------------------------------------------------------------------------
# Item 3: the report's sections
# ---------------------------------------------------------------------------------------------------


def section(lines: list[str], heading: str) -> list[str]:
    """The bullet lines under `heading`, up to the next heading."""
    assert heading in lines, lines
    out: list[str] = []
    for line in lines[lines.index(heading) + 1 :]:
        if line.startswith("#"):
            break
        if line.startswith("- "):
            out.append(line)
    return out


REFUSED = {
    "asset": "asset property L3_writers_cfg: not generated, its text holds \\inter in \\targets",
    "invariant": "invariant property L4_invariant_up: not generated, its text holds proof:deduce",
    "call rule": "call rule property L4_call_w: not generated, its text holds \\result under \\tguard",
}
NOT_GENERATED = [
    "asset mode: `c->` is not an lvalue a property can name",
    "invariant up: no function of its scope is defined in the build: not generated",
    "call rule w: the predicate holds a `;`: not generated",
]
KEPT_PROPERTY = [
    "asset cfg (L3_readers_cfg): 80 functions carry a unit of this property (every function but the readers may read the asset through a pointer)",
    "invariant up (L4_invariant_up): 60 functions carry a unit of this invariant (no `scope`: every function of the build): give a `scope` to bound it (warning above 50)",
    "invariant up: the predicate names lim, which no unit of the build defines as a global: the property does not type where they are not in scope",
    "call rule w: the predicate names idx, which is neither a parameter of w nor a global of the build: the property is \\false (unproven) where the name does not type",
    "call rule w: w names 2 functions; MetAcsl targets them all by name",
    "asset cfg: alias is neither a global of the build nor a parameter of one of its functions: that name is left out",
]
NO_ASSIGNS = (
    "auth gate login (L4_auth_state_login): the declared function(s) fill have no `assigns` at their declaration: "
    "MetAcsl generates nothing for what they write, so the property says nothing about it"
)
SET_ASSIGNS = (
    "asset cfg (L3_writers_cfg): pair assign(s) a set (`assigns \\union(...)` or `{a, b}`), which stops MetAcsl: "
    "the caller(s) flush are left out of the property and not checked. Write one `assigns` term per location in "
    "that contract"
)
PROPERTY_NAMES = [
    {"name": "L3_readers_cfg"},
    {"name": "L3_writers_cfg"},
    {"name": "L4_auth_state_login"},
    {"name": "L4_invariant_up"},
    {"name": "L4_call_w"},
]


def test_a_refusal_of_a_new_kind_is_an_item_without_a_property():
    warnings = [*REFUSED.values(), *NOT_GENERATED]
    lines = gr.security_props_lines({"warnings": warnings, "properties": PROPERTY_NAMES})
    assert section(lines, HEAD_ITEMS) == [f"- {w}" for w in warnings]
    assert HEAD_WARNED not in lines


def test_a_warning_of_a_new_kind_that_kept_its_property_is_listed_apart():
    lines = gr.security_props_lines({"warnings": KEPT_PROPERTY, "properties": PROPERTY_NAMES})
    assert section(lines, HEAD_WARNED) == [f"- {w}" for w in KEPT_PROPERTY]
    assert HEAD_ITEMS not in lines


@pytest.mark.parametrize("warning", [NO_ASSIGNS, SET_ASSIGNS])
def test_a_declared_callee_warning_is_not_an_item_without_a_property(warning):
    lines = gr.security_props_lines({"warnings": [warning], "properties": PROPERTY_NAMES})
    assert section(lines, HEAD_DECLARED_WARNINGS) == [f"- {warning}"]
    assert HEAD_ITEMS not in lines and HEAD_WARNED not in lines


def test_the_real_generator_warnings_land_under_the_right_heading():
    """The texts above are copies: this one goes through security_props.generate."""
    model = _init_model()
    lists = {"assets": [{"name": "ghost", "lvalue": "nowhere", "writers": [], "description": "d"}]}
    doc = sp.generate(model, threat(**lists, call_rules=[{"function": "missing", "predicate": "1", "description": "d"}]))
    lines = gr.security_props_lines(doc)
    items = section(lines, HEAD_ITEMS)
    assert any(line.startswith("- asset ghost:") for line in items), doc["warnings"]
    assert any(line.startswith("- call rule missing:") for line in items), doc["warnings"]


def test_the_initializer_warning_is_a_block_at_the_top_of_the_report():
    doc = sp.generate(flagless(_init_model()), threat(**INIT_LISTS))
    lines = gr.initializer_flags_lines(doc)
    assert lines[0] == "> [!WARNING]" and lines[1].startswith(INIT_BLOCK)
    assert "do not say which calls are initializers" in lines[1] and lines[-1] == ""


def test_the_block_also_shows_for_a_model_with_no_call_sites_at_all():
    """No warning text to read there: the field decides."""
    lines = gr.initializer_flags_lines({"initializer_flags": {"known": False, "properties": []}, "warnings": []})
    assert lines[1].startswith(INIT_BLOCK)


@pytest.mark.parametrize("doc", [None, {}, {"warnings": []}, {"initializer_flags": {"known": True}, "warnings": []}])
def test_no_block_when_nothing_is_missing(doc):
    assert gr.initializer_flags_lines(doc) == []


def test_unchecked_sites_are_listed_per_property():
    unchecked = [
        {"function": "prog.c#flush", "callee": "send_frame", "line": 12, "reason": "a macro hides the call"},
        {"function": "prog.c#helper", "reason": "left out of the targets"},
    ]
    lines = gr.security_props_lines({"warnings": [], "properties": [{"name": NK_CALL, "unchecked": unchecked}]})
    assert section(lines, HEAD_UNCHECKED) == [
        f"- `{NK_CALL}` in `prog.c#flush`, call of `send_frame` at line 12: a macro hides the call",
        f"- `{NK_CALL}` in `prog.c#helper`: left out of the targets",
    ]


def test_declared_callees_are_listed_with_their_callers():
    declared = {
        "set_assigns": [{"callee": "pair", "callers": ["prog.c#a", "prog.c#b"], "assigns": ["\\union(*a, *b)"]}],
        "no_assigns": [{"callee": "fill", "callers": ["prog.c#c"]}],
        "unknown": [{"callee": "opaque", "callers": ["prog.c#d"]}],
    }
    props = [{"name": NK_WRITERS, "declared_callees": declared}]
    found = section(gr.security_props_lines({"warnings": [], "properties": props}), HEAD_CALLEES)
    assert len(found) == 3
    assert "`pair`" in found[0] and "`prog.c#a`, `prog.c#b`" in found[0] and "left out" in found[0]
    assert "`fill`" in found[1] and "`prog.c#c`" in found[1] and "checks nothing" in found[1]
    assert "`opaque`" in found[2] and "`prog.c#d`" in found[2] and "could not be read" in found[2]
    assert all(line.startswith(f"- `{NK_WRITERS}`: ") for line in found)


def test_long_lists_are_capped():
    sites = [{"function": f"prog.c#f{i}", "reason": "r"} for i in range(35)]
    many = [{"callee": "fill", "callers": [f"prog.c#f{i}" for i in range(12)]}]
    props = [{"name": NK_CALL, "unchecked": sites, "declared_callees": {"no_assigns": many}}]
    lines = gr.security_props_lines({"warnings": [f"asset a{i}: not generated" for i in range(33)], "properties": props})
    found = section(lines, HEAD_UNCHECKED)
    assert len(found) == 31 and found[-1].startswith("- ... and 5 more")
    items = section(lines, HEAD_ITEMS)
    assert len(items) == 31 and items[-1].startswith("- ... and 3 more")
    assert "and 4 more" in section(lines, HEAD_CALLEES)[0]


def _unit(function: str, status: str, *evidence: tuple[str, str]) -> dict:
    return {
        "coverage_id": f"prog.c#{function}::l4_call_rule",
        "file": "prog.c",
        "function": function,
        "obligation_class": "l4_call_rule",
        "status": status,
        "evidence": [{"phase": "wp", "result": r, "summary": s, "discharging": False} for r, s in evidence],
    }


@pytest.mark.parametrize(
    "result",
    ["wp_meta_unchecked", "wp_meta_check_not_reported", "wp_meta_simplified_eva_open", BAR_INITIALIZERS, WITHDRAWN],
)
def test_a_barred_unit_is_listed_with_its_reason(result):
    found = section(gr.ledger_bar_lines([_unit("flush", "planned", (result, "because"))]), HEAD_BARRED)
    assert found == [f"- `prog.c#flush::l4_call_rule` (`planned`), `{result}`: because"]


def test_a_unit_closed_since_its_refusal_is_not_listed():
    assert gr.ledger_bar_lines([_unit("flush", "covered", ("wp_meta_unchecked", "old"), ("wp_proven", "new"))]) == []
    assert gr.ledger_bar_lines([_unit("flush", "candidate", ("wp_meta_simplified_eva_open", "old"))]) == []
    assert gr.ledger_bar_lines([_unit("flush", "planned", ("wp_no_credited_goals", "other"))]) == []


def test_the_latest_refusal_of_a_unit_is_the_one_shown():
    unit = _unit("flush", "planned", (WITHDRAWN, "first"), ("wp_meta_simplified_eva_open", "second"))
    assert section(gr.ledger_bar_lines([unit]), HEAD_BARRED) == [
        "- `prog.c#flush::l4_call_rule` (`planned`), `wp_meta_simplified_eva_open`: second"
    ]


def wp_run(function: str, **fields) -> dict:
    return {"function": function, "file": "prog.c", "status": "all_proven", **fields}


def test_the_wp_runs_are_read_where_the_pipeline_keeps_them(run_dir):
    """The canonical report of a function, else the baseline's report of its file (a shared name)."""
    stopped = {
        "status": "analysis_error",
        "reason": "metacsl_set_assigns",
        "metacsl_failure": {"message": "m", "cause": "c", "callees": ["pair", "two"]},
    }
    unnamed = {"security_props": {"code_checks_unnamed": [{"line": 64, "checks": 2, "rows": 3}]}}
    write_json(Path("workspace/reports/wp/flush.json"), wp_run("flush", **stopped))
    write_json(Path("workspace") / baseline_wp_report_rel("prog.c", "store"), wp_run("store", **unnamed))
    write_json(Path("workspace/reports/wp/resize.json"), wp_run("resize"))
    ledger = [{**_unit(fn, "planned"), "file": "prog.c"} for fn in ("flush", "store", "resize", "helper")]
    runs = gr.load_wp_meta_runs(run_dir, ledger)
    assert [r["function"] for r in runs] == ["flush", "store"]
    found = section(gr.wp_meta_run_lines(runs), HEAD_WP_RUNS)
    assert "`metacsl_set_assigns`" in found[0] and "`pair`, `two`" in found[0]
    assert "`code_checks_unnamed`" in found[1] and "line 64" in found[1] and "2 check(s), 3 row(s)" in found[1]


def test_a_check_the_source_audit_refused_is_reported_with_its_reason(run_dir):
    """`code_checks_unnamed` also holds the source audit's rows: a property and why, not a count of rows."""
    audit = {"property": "L6_wiped_buf", "line": 26, "reason": "the line holds another annotation"}
    whole = {"property": "L4_auth_state_login_on_failure", "reason": "1 check(s) placed, 0 `check` in the source"}
    write_json(
        Path("workspace/reports/wp/store.json"),
        wp_run("store", security_props={"code_checks_unnamed": [audit, whole]}),
    )
    runs = gr.load_wp_meta_runs(run_dir, [{**_unit("store", "planned"), "file": "prog.c"}])
    found = section(gr.wp_meta_run_lines(runs), HEAD_WP_RUNS)[0]
    assert "`L6_wiped_buf` at line 26 (the line holds another annotation)" in found
    assert "`L4_auth_state_login_on_failure` (1 check(s) placed" in found and "None" not in found


def test_a_stopped_run_without_a_named_callee_still_says_what_stopped_it(run_dir):
    failure = {"status": "analysis_error", "reason": "metacsl_set_assigns", "metacsl_failure": {"callees": []}}
    write_json(Path("workspace/reports/wp/flush.json"), wp_run("flush", **failure))
    runs = gr.load_wp_meta_runs(run_dir, [_unit("flush", "planned")])
    assert "no callee could be named" in section(gr.wp_meta_run_lines(runs), HEAD_WP_RUNS)[0]


def test_an_unreadable_wp_report_is_no_row(run_dir):
    path = Path("workspace/reports/wp/flush.json")
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8", newline="\n")
    assert gr.load_wp_meta_runs(run_dir, [_unit("flush", "planned")]) == []


def test_a_wp_report_that_is_not_an_object_is_no_row(run_dir):
    write_json(Path("workspace/reports/wp/flush.json"), [1])
    assert gr.load_wp_meta_runs(run_dir, [_unit("flush", "planned")]) == []


def test_a_run_before_phase_3_has_no_wp_report_and_still_gets_its_report(run_dir):
    seed(run_dir, _synthetic_doc())
    state = units()
    Path("workspace/reports/callgraph_dag.json").unlink()
    build_run(run_dir)
    ledger = json.loads(Path("coverage-ledger.json").read_text(encoding="utf-8"))
    write_json(Path("coverage-ledger.json"), sorted([*ledger, *state.values()], key=lambda u: u["coverage_id"]))
    gr.generate(run_dir, run_dir)
    assert HEAD_WP_RUNS not in Path("REPORT.md").read_text(encoding="utf-8")
    assert gr.wp_meta_run_lines([]) == []


def _synthetic_doc() -> dict:
    """A security_props.json the schema accepts, holding every field the report reads."""
    doc = new_kinds_doc()
    for prop in doc["properties"]:
        prop["notes"] = []
    doc["properties"].append(
        {
            "name": NK_SANITIZED,
            "kind": "sanitized",
            "layer": 5,
            "obligation_class": "l5_sanitized",
            "acsl": "meta \\prop, \\name(L5_sanitized_emit), \\targets(\\ALL), \\context(\\calling), \\true;",
            "instances": ["prog.c#helper"],
            "sources": [],
            "notes": [],
        }
    )
    by_name = {p["name"]: p for p in doc["properties"]}
    by_name[NK_CALL]["unchecked"] = [
        {"function": "prog.c#flush", "callee": "send_frame", "line": 12, "reason": "a macro hides the call"}
    ]
    by_name[NK_WRITERS]["declared_callees"] = {
        "set_assigns": [{"callee": "pair", "callers": ["prog.c#store"], "assigns": ["\\union(*a, *b)"]}],
        "no_assigns": [{"callee": "fill", "callers": ["prog.c#store"]}],
        "unknown": [{"callee": "opaque", "callers": ["prog.c#store"]}],
    }
    doc["obligations"]["prog.c#helper"] = [
        {"class": "l4_call_rule", "property": NK_INVARIANT, "reason": "r"},
        {"class": "l5_sanitized", "property": NK_SANITIZED, "reason": "r"},
    ]
    doc["code_checks"] = [{"file": "prog.c", "line": 30, "function": "prog.c#store", "property": NK_WRITERS, "index": 0}]
    doc["warnings"] = [
        REFUSED["asset"],
        KEPT_PROPERTY[0].replace("L3_readers_cfg", NK_READERS),
        NO_ASSIGNS.replace("L4_auth_state_login", NK_WRITERS),
        "the model's call sites do not say which calls are initializers (`initializer`, dump schema 5): nothing here",
    ]
    doc["initializer_flags"] = {"known": False, "properties": [NK_INVARIANT]}
    doc.update(
        {
            "generated_at": "2026-11-19T00:00:00Z",
            "threat_model": {"status": "ok", "path": "THREAT_MODEL.md", "sha256": None, "reason": None},
            "preamble": "",
            "frame": [],
            "summary": {},
        }
    )
    return doc


def test_a_report_of_a_run_holding_every_field_shows_each_in_its_section(run_dir):
    doc = _synthetic_doc()
    assert not sp.validate(doc)
    seed(run_dir, doc)
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])  # wp_meta_unchecked
    L.cmd_ingest_wp([wp_report("store", {}, loaded=[NK_READERS, NK_WRITERS])])  # wp_meta_check_not_reported
    set_unit(cid("resize"), bookkeeping={"eva_verdicts": {NK_MODULE: "unknown"}})
    L.cmd_ingest_wp([wp_report("resize", {}, loaded=[NK_INVARIANT])])  # wp_meta_simplified_eva_open
    L.cmd_ingest_wp([wp_report("helper", {}, loaded=[NK_INVARIANT, NK_SANITIZED])])  # refused, and one credit
    assert units()["prog.c#helper::l5_sanitized"]["status"] == "covered"
    eva_ingest({f"{NK_SANITIZED}@helper": {"unknown": 1}})  # the credit is withdrawn
    state = units()
    assert state["prog.c#helper::l5_sanitized"]["evidence"][-1]["result"] == WITHDRAWN

    stopped = wp_report(
        "flush",
        {},
        status="analysis_error",
        reason="metacsl_set_assigns",
        metacsl_failure={"message": "m", "cause": "c", "callees": ["pair"]},
    )
    assert stopped.is_file()
    wp_report(
        "resize",
        {},
        loaded=[NK_INVARIANT],
        security_props={"properties": [NK_INVARIANT], "code_checks_unnamed": [{"line": 7, "checks": 1, "rows": 2}]},
    )
    Path("workspace/reports/callgraph_dag.json").unlink()  # the ledger's seed only: the report does not read it
    build_run(run_dir)  # the run's other artifacts; its ledger is merged with the seeded units below
    ledger = json.loads(Path("coverage-ledger.json").read_text(encoding="utf-8"))
    merged = sorted([*ledger, *state.values()], key=lambda u: u["coverage_id"])
    write_json(Path("coverage-ledger.json"), merged)

    gr.generate(run_dir, run_dir)
    text = Path("REPORT.md").read_text(encoding="utf-8")
    lines = text.split("\n")
    first_section = text.split("## 2.")[0]
    assert INIT_BLOCK in first_section
    assert section(lines, HEAD_ITEMS) == [f"- {REFUSED['asset']}"]
    assert "80 functions carry a unit" in section(lines, HEAD_WARNED)[0]
    assert section(lines, HEAD_DECLARED_WARNINGS) == [f"- {NO_ASSIGNS.replace('L4_auth_state_login', NK_WRITERS)}"]
    assert "`send_frame` at line 12: a macro hides the call" in section(lines, HEAD_UNCHECKED)[0]
    callees = section(lines, HEAD_CALLEES)
    assert [c for name in ("`pair`", "`fill`", "`opaque`") for c in callees if name in c] == callees
    barred = {line.split("`")[5] for line in section(lines, HEAD_BARRED)}
    assert barred == {
        "wp_meta_unchecked",
        "wp_meta_check_not_reported",
        "wp_meta_simplified_eva_open",
        BAR_INITIALIZERS,
        WITHDRAWN,
    }
    runs = section(lines, HEAD_WP_RUNS)
    assert any("`metacsl_set_assigns`" in r and "`pair`" in r for r in runs)
    assert any("`code_checks_unnamed`" in r and "line 7" in r for r in runs)
    for heading in (HEAD_ITEMS, HEAD_WARNED, HEAD_UNCHECKED, HEAD_CALLEES, HEAD_BARRED, HEAD_WP_RUNS):
        assert first_section.count(heading) == 1, heading


def test_a_run_without_any_of_the_fields_keeps_its_report(tmp_path):
    build_run(tmp_path)
    write_json(tmp_path / "workspace/reports/wp/ber_decode_len.json", wp_run("ber_decode_len"))
    gr.generate(tmp_path, tmp_path)
    text = (tmp_path / "REPORT.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == ENGINE_OFF_REPORT_SHA256


# ---------------------------------------------------------------------------------------------------
# Item 4 and 5: the texts
# ---------------------------------------------------------------------------------------------------

REFUSALS = (
    "wp_meta_simplified_eva_open",
    "wp_meta_unchecked",
    "wp_meta_check_not_reported",
    BAR_INITIALIZERS,
    "metacsl_set_assigns",
    "code_checks_unnamed",
)


@pytest.mark.parametrize("name", REFUSALS)
def test_the_wp_skill_states_every_refusal_of_the_no_goal_credit(name):
    rule = next(
        line
        for line in (ROOT / "skills/framac-wp/SKILL.md").read_text(encoding="utf-8").splitlines()
        if "Security layers via MetAcsl" in line
    )
    assert f"`{name}`" in rule


def test_the_fuzz_skill_no_longer_gives_the_replay_workaround():
    text = (ROOT / "skills/framac-fuzz/SKILL.md").read_text(encoding="utf-8")
    assert "Replay with `--sources` and `--out-bin`, or from the run directory" not in text
    assert "the failure's `file` becomes `unknown`" not in text
    assert "next to the binary" in text


@pytest.mark.parametrize("name", [BAR_INITIALIZERS, WITHDRAWN, "initializer_flags"])
def test_the_guide_names_what_this_package_added(name):
    assert name in (ROOT / "docs/guides/security-properties.md").read_text(encoding="utf-8")


def test_the_entries_this_package_closes_are_no_longer_open():
    eva = (ROOT / "docs/troubleshooting/eva.md").read_text(encoding="utf-8")
    assert "the guard covers the order Eva then WP only" not in eva and WITHDRAWN in eva
    props = (ROOT / "docs/troubleshooting/security-properties.md").read_text(encoding="utf-8")
    assert "**Open pipeline gap (a model without flags):**" not in props
    assert "`REPORT.md` does not show `unchecked` or `declared_callees`" not in props
