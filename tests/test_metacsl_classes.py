"""
Package D2 of docs/plans/metacsl-exploitation-plan.md: the classes l3_isolation, l4_invariant and
l4_call_rule (asset writers and readers, invariants, call rules; names in section 3.3 of the plan)
through the ledger, the WP goal classes, the schemas and the report. Also the rule that `ingest-wp`
gives no no-goal credit to a unit Eva left a check open for, and the report's heading for a forwarding
sink whose property was kept.

No Docker and no fixture file: the security_props.json and the reports are built here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import generate_report as gr
import ledger as L
import run_wp_function as R
import security_props as sp
from conftest import ROOT, write_json

NK_MODULE = "libprog.a"
NK_PROPS = "workspace/reports/security_props.json"
NK_DAG = "workspace/reports/callgraph_dag.json"
NK_WRITERS = "L3_writers_session"
NK_READERS = "L3_readers_session"
NK_INVARIANT = "L4_invariant_len_le_cap"
NK_CALL = "L4_call_send_frame"
NK_SANITIZED = "L5_sanitized_emit"
NK_NEW_CLASSES = ("l3_isolation", "l4_invariant", "l4_call_rule")
# function -> (class, the properties with an instance in it)
NK_UNITS = {
    "store": ("l3_isolation", [NK_READERS, NK_WRITERS]),
    "resize": ("l4_invariant", [NK_INVARIANT]),
    "flush": ("l4_call_rule", [NK_CALL]),
}
NK_GOALS = {
    NK_WRITERS: "\\separated(p, &session)",
    NK_READERS: "\\separated(q, &session)",
    NK_INVARIANT: "len <= cap",
    NK_CALL: "ready != 0",
}
NK_KINDS = {
    NK_WRITERS: ("asset_writers", 3, "l3_isolation"),
    NK_READERS: ("asset_readers", 3, "l3_isolation"),
    NK_INVARIANT: ("invariant", 4, "l4_invariant"),
    NK_CALL: ("call_rule", 4, "l4_call_rule"),
}


def new_kinds_doc() -> dict:
    """A security_props.json holding one property of each new kind (the fields the pipeline reads)."""
    properties = []
    obligations: dict[str, list[dict]] = {}
    for fn, (cls, names) in NK_UNITS.items():
        for name in names:
            kind, layer, _ = NK_KINDS[name]
            properties.append(
                {
                    "name": name,
                    "kind": kind,
                    "layer": layer,
                    "obligation_class": cls,
                    "acsl": f"meta \\prop, \\name({name}), \\targets({fn}), \\context(\\writing), \\true;",
                    "instances": [f"prog.c#{fn}"],
                    "sources": [],
                }
            )
            obligations.setdefault(f"prog.c#{fn}", []).append(
                {"class": cls, "property": name, "reason": f"{kind} of the threat model"}
            )
    # store also writes through a pointer: its plain frame obligation is another unit.
    obligations["prog.c#store"].append({"class": "l3_frame", "property": "L3_frame", "reason": "writes *p"})
    return {
        "schema_version": 1,
        "properties": properties,
        "obligations": obligations,
        "initializer_flags": {"known": True},
        "warnings": [],
    }


def old_kinds_doc() -> dict:
    """A report without any property of the new kinds."""
    ob = {"class": "l5_sanitized", "property": NK_SANITIZED, "reason": "calls the sink"}
    return {
        "schema_version": 1,
        "properties": [],
        "obligations": {"prog.c#flush": [ob]},
        "initializer_flags": {"known": True},
        "warnings": [],
    }


def seed(run: Path, doc: dict) -> dict[str, dict]:
    dag = {
        "callgraph_source": "frama_c",
        "modules": {NK_MODULE: {"tier": "Tier 1A (Untrusted Binary / Network Parser)"}},
        "functions": {
            name: {"name": name, "file": "prog.c", "module": NK_MODULE, "wave": 0, "has_loops": False}
            for name in ("store", "resize", "flush", "helper")
        },
    }
    write_json(run / NK_PROPS, doc)
    write_json(run / NK_DAG, dag)
    L.cmd_seed(run / NK_DAG, [], "frama_c")
    return units()


def units() -> dict[str, dict]:
    return L.load_state()[0]


def cid(function: str) -> str:
    return f"prog.c#{function}::{NK_UNITS[function][0]}"


def wp_report(
    function: str, goals: dict[str, str], loaded: list[str] | None = None, status: str = "all_proven", **extra
) -> Path:
    """
    A WP report of `function`: four proven RTE goals and one goal per entry of `goals` (property name ->
    predicate), named as run_wp_function.name_meta_goal names them and counted by its own class map.
    `loaded` is what MetAcsl loaded for the function (default: the names of `goals`).
    """
    items = [
        {"file": "prog.c", "function": function, "line": 3 + i, "kind": "mem_access", "annotation": f"\\valid(p + {i})"}
        for i in range(4)
    ]
    items += [
        {
            "file": f"security_meta_{function}.c",
            "function": function,
            "line": 6 + i,
            "kind": "user assertion",
            "annotation": f"{name}: meta: {predicate}",
        }
        for i, (name, predicate) in enumerate(sorted(goals.items()))
    ]
    by_class: dict[str, dict[str, int]] = {}
    for item in items:
        item["status"] = "Valid"
        item["obligation_class"] = R.goal_obligation_class(item)
        by_class.setdefault(item["obligation_class"], {"proven": 0, "proven_under_hyp": 0, "unproven": 0})[
            "proven"
        ] += 1
    report = {
        "status": status,
        "function": function,
        "file": "prog.c",
        "wp_model": "Typed",
        "total_goals": len(items),
        "proven_count": len(items),
        "soundness": {"ok": status == "all_proven", "tier_a_aborts": [], "tier_b_unsound": [], "reduced_checks": []},
        "by_obligation_class": by_class,
        "unproven_goals": [],
        "layer_goals": [i for i in items if i["obligation_class"] in R.LAYER_CLASSES],
        "security_props": {
            "props": NK_PROPS,
            "function_id": f"prog.c#{function}",
            "properties": sorted(goals) if loaded is None else loaded,
            "extra_sources": [],
        },
        "limits": {
            "vacuity": {"status": "consistent", "doomed": [], "dead_goals": 0},
            "missing_spec_callees": [],
            "trivial_layer_clauses": [],
            "unchecked_layer_clauses": sorted(goals),
            "classes_without_real_clause": [],
        },
        **extra,
    }
    path = Path(f"workspace/reports/wp/{function}.json")
    write_json(path, report)
    return path


def set_unit(coverage_id: str, **fields) -> None:
    """Rewrite fields of one ledger unit on disk (`bookkeeping` is merged)."""
    ledger = json.loads(L.LEDGER.read_text(encoding="utf-8"))
    for unit in ledger:
        if unit["coverage_id"] == coverage_id:
            unit.setdefault("bookkeeping", {}).update(fields.pop("bookkeeping", {}))
            unit.update(fields)
    write_json(L.LEDGER, ledger)


def eva_covered(coverage_id: str, result: str) -> None:
    """Make a unit covered by Eva alone: one module's `valid` verdict and its discharging evidence."""
    unit = units()[coverage_id]
    L.add_evidence(
        unit, "eva", "run_eva_slice.py", result, True, f"workspace/reports/eva/{NK_MODULE}.json", "Valid under Eva."
    )
    set_unit(
        coverage_id, status="covered", evidence=unit["evidence"], bookkeeping={"eva_verdicts": {NK_MODULE: "valid"}}
    )


# ---------------------------------------------------------------------------------------------------
# The class lists
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_new_classes_are_metacsl_classes_everywhere():
    for cls in NK_NEW_CLASSES:
        assert cls in L.METACSL_CLASSES and cls in L.SECURITY_CLASSES
        assert cls in R.LAYER_CLASSES and cls in gr.CLASSES
    # The plain frame obligation is a security class WP's own goals credit: no MetAcsl class.
    assert "l3_frame" in L.SECURITY_CLASSES and "l3_frame" not in L.METACSL_CLASSES
    assert "l3_frame" not in R.LAYER_CLASSES
    assert set(L.SECURITY_CLASSES) == {"l3_frame", *L.METACSL_CLASSES} == set(gr.CLASSES) - {"rte", "l2_termination"}
    assert set(L.METACSL_CLASSES) == R.LAYER_CLASSES


@pytest.mark.unit
@pytest.mark.parametrize("schema", ["coverage-ledger", "agent-result", "findings"])
def test_the_schemas_take_the_new_classes(schema):
    text = (ROOT / "schemas" / f"{schema}.schema.json").read_text(encoding="utf-8")
    doc = json.loads(text)
    patterns = [
        node["pattern"]
        for node in _walk(doc)
        if isinstance(node, dict) and "::(" in str(node.get("pattern") or "") and node.get("type") == "string"
    ]
    assert patterns, schema
    for pattern in patterns:
        for cls in ("rte", "l2_termination", *L.SECURITY_CLASSES):
            assert re.search(pattern, f"src/prog.c#store::{cls}"), (schema, cls)
        assert not re.search(pattern, "src/prog.c#store::l3_isolations")
        assert not re.search(pattern, "src/prog.c#store::l4_call")
    enums = [
        node["enum"]
        for node in _walk(doc)
        if isinstance(node, dict) and isinstance(node.get("enum"), list) and "l5_sanitized" in node["enum"]
    ]
    for enum in enums:
        assert set(enum) == {"rte", "l2_termination", *L.SECURITY_CLASSES}, schema
    assert enums or schema == "findings"


def _walk(node):
    yield node
    for child in node.values() if isinstance(node, dict) else node if isinstance(node, list) else ():
        yield from _walk(child)


# ---------------------------------------------------------------------------------------------------
# run_wp_function: the class of a goal
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kind", "annotation", "cls"),
    [
        # The generated goals of the new kinds. A writers goal is a \separated: its name decides first.
        ("user assertion", "L3_writers_session: meta: \\separated(p, &session)", "l3_isolation"),
        ("user assertion", "L3_readers_session: meta: \\separated(q, &session)", "l3_isolation"),
        ("precondition", "L4_invariant_len_le_cap: meta: len <= cap", "l4_invariant"),
        ("postcondition", "L4_invariant_len_le_cap: meta: len <= cap", "l4_invariant"),
        ("precondition of send_frame", "L4_call_send_frame: meta: ready != 0", "l4_call_rule"),
        # A name that holds another kind's word is its own kind.
        ("user assertion", "L3_writers_auth_state: meta: \\separated(p, &auth_state)", "l3_isolation"),
        ("precondition", "L4_invariant_call_depth: meta: depth <= 8", "l4_invariant"),
        ("precondition of auth_state_get", "L4_call_auth_state_get: meta: ready != 0", "l4_call_rule"),
        ("user assertion", "L4_auth_state_call_login: meta: \\separated(p, &auth_ok)", "l4_auth_state"),
        ("precondition of invariant_check", "L4_auth_required_invariant_check: meta: auth_ok != 0", "l4_auth_required"),
        # The kinds that were there keep their class.
        ("user assertion", "L4_auth_state_login: meta: \\separated(p, &auth_ok)", "l4_auth_state"),
        ("precondition of admin", "L4_auth_required_login: meta: auth_ok != 0", "l4_auth_required"),
        ("user assertion", "L5_sanitized_emit: meta: \\initialized(buf + (0 .. n - 1))", "l5_sanitized"),
        ("postcondition", "L6_wiped_key: meta: key[0] == 0", "l6_wiped"),
        ("user assertion", "L6_no_leak_key: meta: \\separated(p, &key)", "l6_no_leak"),
        # The plain frame obligation, and hand-named clauses: no MetAcsl class.
        ("assigns", "assigns *p;", "l3_frame"),
        ("assigns", "L3_frame: assigns *p;", "l3_frame"),
        ("precondition", "L3_frame_sep: \\separated(p, q)", "l3_frame"),
        ("precondition", "L3_isolation_helper: p != \\null", "rte"),
        ("postcondition", "L3_writer_done: \\result == 0", "rte"),
        ("precondition", "L4_caller_ready: ready != 0", "rte"),
        ("precondition", "L4_callrule_ready: ready != 0", "rte"),
        ("precondition", "L4_call: ready != 0", "rte"),
        ("precondition", "L5_call_ready: ready != 0", "rte"),
        ("precondition", "L4_writers_x: p != \\null", "rte"),
        ("loop variant", "n - i", "l2_termination"),
        ("mem_access", "\\valid(p)", "rte"),
    ],
)
def test_goal_obligation_class(kind, annotation, cls):
    assert R.goal_obligation_class({"kind": kind, "annotation": annotation}) == cls


@pytest.mark.unit
def test_a_layer_3_goal_is_read_by_the_trivial_clause_check_like_the_others(tmp_path):
    """layer_clause_limits lists a generated goal it cannot read back; an L3 name is no exception."""
    c_file = tmp_path / "prog.c"
    c_file.write_text("void store(int *p) { *p = 0; }\n", encoding="utf-8")
    goals = [
        {"file": "security_meta_store.c", "kind": "user assertion", "annotation": f"{name}: meta: {predicate}"}
        for name, predicate in (
            (NK_WRITERS, NK_GOALS[NK_WRITERS]),
            (NK_INVARIANT, NK_GOALS[NK_INVARIANT]),
            (NK_CALL, NK_GOALS[NK_CALL]),
            (NK_SANITIZED, "\\initialized(buf)"),
        )
    ]
    for goal in goals:
        goal["obligation_class"] = R.goal_obligation_class(goal)
    limits = R.layer_clause_limits(goals, c_file)
    assert limits["unchecked_layer_clauses"] == sorted([NK_WRITERS, NK_INVARIANT, NK_CALL, NK_SANITIZED])
    assert limits["trivial_layer_clauses"] == [] and limits["classes_without_real_clause"] == []


# ---------------------------------------------------------------------------------------------------
# The seed
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_seed_plans_a_unit_per_function_and_new_class(run_dir):
    seeded = seed(run_dir, new_kinds_doc())
    for fn, (cls, names) in NK_UNITS.items():
        unit = seeded[f"prog.c#{fn}::{cls}"]
        assert unit["status"] == "planned" and unit["obligation_class"] == cls
        assert unit["bookkeeping"]["security_properties"] == sorted(names)
    # Writers and readers of one asset are one unit; the plain frame obligation of the function is another.
    frame = seeded["prog.c#store::l3_frame"]
    assert frame["status"] == "planned" and "security_properties" in frame["bookkeeping"]
    assert frame["bookkeeping"]["security_properties"] == ["L3_frame"]
    assert sorted(c.split("::")[1] for c in seeded if c.startswith("prog.c#store::")) == [
        "l3_frame",
        "l3_isolation",
        "rte",
    ]
    assert sorted(c.split("::")[1] for c in seeded if c.startswith("prog.c#helper::")) == ["rte"]
    assert not L.validate_ledger(list(seeded.values()))


@pytest.mark.unit
def test_without_a_new_kind_the_seed_holds_no_new_class(run_dir):
    seeded = seed(run_dir, old_kinds_doc())
    assert sorted(seeded) == [
        "prog.c#flush::l5_sanitized",
        "prog.c#flush::rte",
        "prog.c#helper::rte",
        "prog.c#resize::rte",
        "prog.c#store::rte",
    ]


# ---------------------------------------------------------------------------------------------------
# ingest-wp
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_ingest_wp_credits_the_generated_goals_of_the_new_kinds(run_dir):
    seed(run_dir, new_kinds_doc())
    reports = [wp_report(fn, {name: NK_GOALS[name] for name in names}) for fn, (_, names) in NK_UNITS.items()]
    by_class = json.loads(reports[0].read_text(encoding="utf-8"))["by_obligation_class"]
    assert by_class == {
        "rte": {"proven": 4, "proven_under_hyp": 0, "unproven": 0},
        "l3_isolation": {"proven": 2, "proven_under_hyp": 0, "unproven": 0},
    }
    stats = L.cmd_ingest_wp(reports)
    after = units()
    for fn in NK_UNITS:
        unit = after[cid(fn)]
        assert unit["status"] == "covered", unit
        assert unit["evidence"][-1]["result"] == "wp_proven" and unit["evidence"][-1]["discharging"]
    # The two \separated goals of the asset are no frame goals: store's frame unit has no goal here.
    frame = after["prog.c#store::l3_frame"]
    assert frame["status"] == "covered" and frame["evidence"][-1]["result"] == "wp_qed_simplified"
    assert stats["covered"] == 3 + 3 + 1  # the three new-class units, their functions' rte units, the frame unit
    assert not L.validate_ledger(list(after.values()))


@pytest.mark.unit
def test_an_unproven_goal_of_a_new_kind_blocks_its_unit_only(run_dir):
    seed(run_dir, new_kinds_doc())
    path = wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]}, status="unproven_goals_remain")
    report = json.loads(path.read_text(encoding="utf-8"))
    goal = report["layer_goals"][0]
    report["by_obligation_class"]["l4_call_rule"] = {"proven": 0, "proven_under_hyp": 0, "unproven": 1}
    report["unproven_goals"] = [{**goal, "status": "Unknown"}]
    write_json(path, report)
    L.cmd_ingest_wp([path])
    unit = units()[cid("flush")]
    assert unit["status"] == "blocked" and unit["evidence"][-1]["result"] == "wp_unproven"
    assert NK_CALL in unit["unresolved"][0]
    assert units()["prog.c#flush::rte"]["status"] != "blocked"


@pytest.mark.unit
@pytest.mark.parametrize("fn", sorted(NK_UNITS))
def test_a_unit_metacsl_left_no_goal_for_is_credited_only_when_its_properties_were_loaded(run_dir, fn):
    seed(run_dir, new_kinds_doc())
    names = NK_UNITS[fn][1]
    # Not loaded (or one of two loaded): nothing was decided. An l3_isolation unit is no frame unit,
    # which Qed may discharge without a goal.
    L.cmd_ingest_wp([wp_report(fn, {}, loaded=names[:-1])])
    unit = units()[cid(fn)]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == "wp_no_credited_goals"
    L.cmd_ingest_wp([wp_report(fn, {}, loaded=names)])
    unit = units()[cid(fn)]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified"
    assert all(name in unit["evidence"][-1]["summary"] for name in names)


@pytest.mark.unit
@pytest.mark.parametrize("verdict", sorted(L.EVA_BLOCKING))
@pytest.mark.parametrize("fn", ["flush", "store"])
def test_no_goal_is_no_credit_while_an_eva_module_leaves_a_check_open(run_dir, fn, verdict):
    """docs/troubleshooting/eva.md: covered by `wp_meta_simplified` although the Eva check is Unknown."""
    seed(run_dir, new_kinds_doc())
    names = NK_UNITS[fn][1]
    set_unit(cid(fn), bookkeeping={"eva_verdicts": {"libother.a": "valid", NK_MODULE: verdict, "libdead.a": "dead"}})
    stats = L.cmd_ingest_wp([wp_report(fn, {}, loaded=names)])
    unit = units()[cid(fn)]
    assert unit["status"] == "planned", unit["evidence"][-1]
    last = unit["evidence"][-1]
    assert last["result"] == "wp_meta_simplified_eva_open" and not last["discharging"] and last["phase"] == "wp"
    assert f"'{NK_MODULE}'" in last["summary"] and "libother.a" not in last["summary"]
    assert unit["bookkeeping"]["eva_verdicts"][NK_MODULE] == verdict
    # The function's RTE unit is credited as before: 4 proven goals.
    assert units()[f"prog.c#{fn}::rte"]["status"] == "covered"
    assert stats["covered"] == (2 if fn == "store" else 1)  # store's frame unit has no goal either
    # The module's next report proves the check: the same WP report now credits the unit.
    set_unit(cid(fn), bookkeeping={"eva_verdicts": {"libother.a": "valid", NK_MODULE: "valid", "libdead.a": "dead"}})
    L.cmd_ingest_wp([wp_report(fn, {}, loaded=names)])
    unit = units()[cid(fn)]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified"
    assert not L.validate_ledger(list(units().values()))


@pytest.mark.unit
def test_the_eva_guard_holds_for_the_classes_that_were_there(run_dir):
    seed(run_dir, old_kinds_doc())
    coverage_id = "prog.c#flush::l5_sanitized"
    set_unit(coverage_id, bookkeeping={"eva_verdicts": {NK_MODULE: "unknown"}})
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_SANITIZED])])
    unit = units()[coverage_id]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == "wp_meta_simplified_eva_open"


@pytest.mark.unit
@pytest.mark.parametrize("verdict", ["valid", "dead", "none"])
def test_a_verdict_that_does_not_block_keeps_the_no_goal_credit(run_dir, verdict):
    seed(run_dir, new_kinds_doc())
    set_unit(cid("flush"), bookkeeping={"eva_verdicts": {NK_MODULE: verdict}})
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified"


@pytest.mark.unit
def test_a_proven_goal_credits_the_unit_whatever_eva_left_open(run_dir):
    """Eva's Unknown leaves the property to WP: a goal WP proves is the proof."""
    seed(run_dir, new_kinds_doc())
    set_unit(cid("flush"), bookkeeping={"eva_verdicts": {NK_MODULE: "unknown"}})
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_proven"


@pytest.mark.unit
def test_the_sweep_blocks_a_no_goal_credit_given_before_eva_left_the_check_open(run_dir):
    """The order WP then Eva: the plain ingest leaves the earlier credit, the end-of-run re-proof does not."""
    seed(run_dir, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    assert units()[cid("flush")]["status"] == "covered"
    set_unit(cid("flush"), bookkeeping={"eva_verdicts": {NK_MODULE: "unknown"}})
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified_eva_open"
    stats = L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])], sweep=True)
    unit = units()[cid("flush")]
    assert unit["status"] == "blocked" and unit["evidence"][-1]["result"] == "wp_sweep_not_reproven"
    assert stats["blocked"] == 1 and units()["prog.c#flush::rte"]["status"] == "covered"


@pytest.mark.unit
@pytest.mark.parametrize("status", ["wp_aborted", "unsound_proof"])
def test_a_rejected_wp_run_blocks_an_eva_covered_unit_it_has_no_goal_for_as_it_does_an_rte_unit(run_dir, status):
    """
    Package B's note: a WP run the soundness gate rejects blocks every unit of the function, an
    Eva-covered MetAcsl unit WP has no goal for included. It is what happens to an Eva-covered rte unit.
    """
    seed(run_dir, new_kinds_doc())
    meta, rte = cid("flush"), "prog.c#flush::rte"
    eva_covered(meta, "eva_meta_valid")
    eva_covered(rte, "eva_all_valid")
    soundness = {"ok": False, "tier_a_aborts": ["Goal aborted"], "tier_b_unsound": ["Missing assigns"]}
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL], status=status, soundness=soundness)])
    after = units()
    for coverage_id in (meta, rte):
        unit = after[coverage_id]
        assert unit["status"] == "blocked", coverage_id
        assert unit["evidence"][-1]["result"] == f"wp_{status}" and not unit["evidence"][-1]["discharging"]
        assert unit["unresolved"] and unit["unresolved"][0].startswith(f"{status}: ")
        # The Eva verdict and its evidence stay on the unit.
        assert unit["bookkeeping"]["eva_verdicts"] == {NK_MODULE: "valid"}
        assert any(e["phase"] == "eva" and e["discharging"] for e in unit["evidence"])
    assert not L.validate_ledger(list(after.values()))


# ---------------------------------------------------------------------------------------------------
# ingest-eva (package B's region): the new classes are filed like the other MetAcsl classes
# ---------------------------------------------------------------------------------------------------


def _eva_section(counts: dict[str, dict[str, int]]) -> dict:
    """An Eva report's `security_props` section: per `property@function`, the rows per status."""
    instances = []
    for key, found in counts.items():
        name, _, fn = key.partition("@")
        entry = {"property": name, "instance": f"prog.c#{fn}", "valid": 0, "unknown": 0, "invalid": 0, "dead": 0}
        instances.append({**entry, "other": 0, **found})
    return {"props": NK_PROPS, "meta_file": "workspace/reports/eva/meta_prog.c", "instances": instances}


@pytest.mark.unit
def test_ingest_eva_files_the_checks_of_the_new_kinds(run_dir):
    seeded = seed(run_dir, new_kinds_doc())
    section = _eva_section(
        {
            f"{NK_WRITERS}@store": {"valid": 2},
            f"{NK_READERS}@store": {"valid": 1},
            f"{NK_INVARIANT}@resize": {"valid": 2, "unknown": 1},
            f"{NK_CALL}@flush": {"valid": 1},
        }
    )
    candidates: dict[str, dict] = {}
    touched: set[str] = set()
    report = {"status": "ok", "module": NK_MODULE, "reduced_checks": []}
    filed, opened = L._ingest_eva_meta(
        seeded, candidates, section, NK_MODULE, report, f"workspace/reports/eva/{NK_MODULE}.json", {}, touched
    )
    assert (filed, opened) == (3, 0) and touched == {cid(fn) for fn in NK_UNITS}
    assert seeded[cid("store")]["bookkeeping"]["eva_verdicts"] == {NK_MODULE: "valid"}
    assert seeded[cid("store")]["evidence"][-1]["result"] == "eva_meta_valid"
    assert seeded[cid("flush")]["evidence"][-1]["result"] == "eva_meta_valid"
    assert seeded[cid("resize")]["bookkeeping"]["eva_verdicts"] == {NK_MODULE: "unknown"}
    assert seeded[cid("resize")]["evidence"][-1]["result"] == "eva_meta_unknown"
    # The frame unit of store is no MetAcsl class: Eva's checks say nothing about it.
    assert not seeded["prog.c#store::l3_frame"]["evidence"]
    assert "eva_verdicts" not in seeded["prog.c#store::l3_frame"]["bookkeeping"]


# ---------------------------------------------------------------------------------------------------
# The report and the briefs
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_report_lists_the_new_classes_and_only_when_they_have_units(run_dir):
    seeded = seed(run_dir, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    table = gr.assurance_table(list(units().values()))
    rows = [line.split("|")[1].strip() for line in table[2:-1]]
    assert rows == ["`rte`", "`l3_frame`", "`l3_isolation`", "`l4_invariant`", "`l4_call_rule`"]
    call_rule = next(line for line in table if line.startswith("| `l4_call_rule`"))
    assert [c.strip() for c in call_rule.split("|")[2:4]] in (["1", "0"], ["0", "1"])  # covered
    total = table[-1].replace("*", "").split("|")[2:-1]
    assert sum(int(c) for c in total) == len(seeded)
    # Without a unit of a new class the table is what it was.
    old = [u for u in units().values() if u["obligation_class"] not in NK_NEW_CLASSES]
    assert not any(cls in line for line in gr.assurance_table(old) for cls in NK_NEW_CLASSES)


@pytest.mark.unit
def test_a_kept_forwarding_sink_is_not_listed_as_an_item_without_a_property():
    kept = (
        "output sink send_msg: it forwards to tcp_send, but the call through `ctx->backend->send` in send_msg "
        "(prog.c:40) reaches the declared sink(s) tcp_send and also rtu_send, which reach(es) none. Its property "
        "stays at its own calls (which is before the buffer is complete when a callee of send_msg completes it). "
        "Declare rtu_send (or what they transmit through) as output sinks to have the bytes checked where they leave"
    )
    without = [
        "secret tok: a returned secret gets no property",
        "output sink log_it: msg is not one of its parameters",
        "output sink forward_all: no pointer parameter to state a property on (give `params`): L5 not generated",
    ]
    lines = gr.security_props_lines({"warnings": [without[0], kept, *without[1:], "the model has no call sites"]})
    first = lines.index("### Threat-model items without a property")
    second = lines.index("### Output sinks whose property is checked before their buffer is complete")
    assert first == 0 and second > first
    assert [line for line in lines[first:second] if line.startswith("- ")] == [f"- {w}" for w in without]
    assert [line for line in lines[second:] if line.startswith("- ")] == [f"- {gr.md_escape(kept)}"]
    assert lines[-1] == ""
    # Each heading appears only with an item of its own, and the first section is what it was.
    assert gr.security_props_lines({"warnings": without}) == [
        "### Threat-model items without a property",
        "",
        *(f"- {w}" for w in without),
        "",
    ]
    only_kept = gr.security_props_lines({"warnings": [kept]})
    assert only_kept[0] == "### Output sinks whose property is checked before their buffer is complete"
    assert "### Threat-model items without a property" not in only_kept
    assert gr.security_props_lines({"warnings": ["the model has no call sites"]}) == []
    assert gr.security_props_lines(None) == []


@pytest.mark.unit
def test_a_brief_names_the_properties_of_the_new_kinds_with_their_class():
    """workspace_overlay.py hands security_props.brief_entries to the brief as it is: no class is filtered."""
    entries = sp.brief_entries(new_kinds_doc(), "prog.c", "store")
    by_name = {e["property"]: e for e in entries}
    assert set(by_name) == {"L3_frame", NK_WRITERS, NK_READERS}
    assert by_name[NK_WRITERS]["obligation_class"] == "l3_isolation" and by_name[NK_WRITERS]["layer"] == 3
    assert by_name["L3_frame"]["obligation_class"] == "l3_frame"
    (call,) = sp.brief_entries(new_kinds_doc(), "prog.c", "flush")
    assert call["obligation_class"] == "l4_call_rule" and call["kind"] == "call_rule" and "metacsl" in call
