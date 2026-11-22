"""
Package G of docs/plans/metacsl-exploitation-plan.md: the final wiring of the MetAcsl work.

- phase0_model.py carries the dump's `initializer` flag of a call site into the model;
- ledger.py refuses the no-goal credit (`wp_meta_simplified`) where a property is known not to be
  checked (`unchecked`, an initializer check that was not placed or that the run did not report),
  and keys in-code checks by (file, line, index);
- run_wp_function.py names the goals of in-code checks from `code_checks` and recognises MetAcsl's
  `meta_annotate.ml` line 675 failure;
- run_eva_slice.py and fuzz_build.py build the module meta file from `security_props.for_engine`.

The ledger tests reuse the helpers of tests/test_metacsl_classes.py (a seeded one-file run).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import fuzz_build
import ledger as L
import phase0_model as pm
import run_eva_slice
import run_wp_function as rwf
from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images, write_json
from test_metacsl_classes import NK_CALL, NK_GOALS, NK_MODULE, cid, new_kinds_doc, seed, units, wp_report
from test_metacsl_eacsl import ALL_PROPERTY_NAMES, META_EACSL_FIXTURE, fixture_props, write_props
from test_metacsl_eacsl import DEFAULT_PROPS as EACSL_PROPS
from test_metacsl_eacsl import OUT_BIN as EACSL_OUT
from test_metacsl_eacsl import SOURCES as EACSL_SOURCES
from test_metacsl_eva import MB_AUTH_STATE, meta_run, prop_of, props_doc, static_section  # noqa: F401
from test_security_props import (
    FIX,
    INIT_DIR,
    INIT_GATE,
    INIT_LISTS,
    INIT_STRONG,
    _forward_wp,
    _ledger_units,
    _model_with_initializer_flags,
    _one_file_target,
    _seed_one_file,
)

# ---------------------------------------------------------------------------------------------------
# Item 1: the model keeps the dump's initializer flag
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_model_carries_the_initializer_flag_of_a_call_site():
    dump_fn = {
        "calls": [
            {"name": "net_send", "indirect": False, "literal_args": {}, "initializer": True, "loc": "/t/a.c:4"},
            {"name": "net_send", "indirect": False, "literal_args": {}, "initializer": False, "loc": "/t/a.c:6"},
            {"indirect": True, "expr": "fp", "loc": "/t/a.c:7"},
        ]
    }
    assert pm._body_facts(dump_fn)["call_sites"] == [
        {"callee": "net_send", "line": 4, "literals": {}, "initializer": True},
        {"callee": "net_send", "line": 6, "literals": {}, "initializer": False},
    ]
    # A dump before schema 5 does not say: the key stays absent ("not known"), never false.
    older = {"calls": [{"name": "g", "indirect": False, "literal_args": {}, "loc": "/t/a.c:6"}]}
    assert pm._body_facts(older)["call_sites"] == [{"callee": "g", "line": 6, "literals": {}}]


# ---------------------------------------------------------------------------------------------------
# Item 2: the ledger half of package E
# ---------------------------------------------------------------------------------------------------

SITE = {"function": "prog.c#flush", "callee": "send_frame", "line": 12}
INIT_CHECK = {**SITE, "at": "before", "check": "/*@ check L4_call_send_frame: ready != 0; */"}
PLACED = {"file": "prog.c", "line": 12, "function": "prog.c#flush", "property": NK_CALL, "index": 0}


def _with(doc: dict, name: str, **fields) -> dict:
    for p in doc["properties"]:
        if p["name"] == name:
            p.update(fields)
    return doc


@pytest.mark.unit
@pytest.mark.parametrize("goals", ["none", "proven"])
def test_a_unit_with_an_unchecked_initializer_site_is_never_credited(run_dir, goals):
    """
    flush is an instance of the call rule (a statement call elsewhere) and also calls the callee in an
    initializer no check could be written for (`unchecked`). WP proving the statement call's goal, or
    MetAcsl leaving none, says nothing about that site: the unit is blocked, naming it.
    """
    why = "an initializer call of send_frame: an argument the check cannot repeat"
    seed(run_dir, _with(new_kinds_doc(), NK_CALL, unchecked=[{**SITE, "reason": why}]))
    found = {NK_CALL: NK_GOALS[NK_CALL]} if goals == "proven" else {}
    stats = L.cmd_ingest_wp([wp_report("flush", found, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    last = unit["evidence"][-1]
    assert unit["status"] == "blocked" and last["result"] == "wp_meta_unchecked" and not last["discharging"]
    assert "line 12" in unit["unresolved"][0] and why in unit["unresolved"][0] and NK_CALL in unit["unresolved"][0]
    assert stats["blocked"] == 1 and units()["prog.c#flush::rte"]["status"] == "covered"
    assert not L.validate_ledger(list(units().values()))


@pytest.mark.unit
def test_a_function_left_out_of_the_targets_is_never_credited(run_dir):
    """The obligation entry carries `unchecked` (a callee whose `assigns` stops MetAcsl): no credit."""
    doc = new_kinds_doc()
    why = "calls two, whose `assigns` holds a set (\\union(...) or braces): MetAcsl stops on it"
    doc["obligations"]["prog.c#helper"] = [
        {"class": "l4_call_rule", "property": NK_CALL, "reason": "call rule", "unchecked": why}
    ]
    seed(run_dir, doc)
    L.cmd_ingest_wp([wp_report("helper", {}, loaded=[NK_CALL])])
    unit = units()["prog.c#helper::l4_call_rule"]
    assert unit["status"] == "blocked" and unit["evidence"][-1]["result"] == "wp_meta_unchecked"
    assert why in unit["unresolved"][0]


@pytest.mark.unit
def test_an_initializer_check_that_was_not_written_bars_the_credit(run_dir):
    """`init_checks` lists a site but `code_checks` holds no check written for it: nothing checked it."""
    seed(run_dir, _with(new_kinds_doc(), NK_CALL, init_checks=[INIT_CHECK]))
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    assert unit["status"] == "blocked" and unit["evidence"][-1]["result"] == "wp_meta_unchecked"
    assert "not written" in unit["unresolved"][0] and "send_frame" in unit["unresolved"][0]


@pytest.mark.unit
def test_a_written_check_the_run_did_not_report_bars_the_no_goal_credit(run_dir):
    """The check is in the work tree but the WP run has no goal of the class: a stale tree, not a proof."""
    doc = _with(new_kinds_doc(), NK_CALL, init_checks=[INIT_CHECK])
    doc["code_checks"] = [PLACED]
    seed(run_dir, doc)
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    unit = units()[cid("flush")]
    last = unit["evidence"][-1]
    assert unit["status"] == "planned" and last["result"] == "wp_meta_check_not_reported", last
    assert "line(s) 12" in last["summary"] and not last["discharging"]
    # With the check's goal proven, the unit is covered by that proof.
    L.cmd_ingest_wp([wp_report("flush", {NK_CALL: NK_GOALS[NK_CALL]})])
    unit = units()[cid("flush")]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_proven"


@pytest.mark.unit
def test_the_no_goal_credit_stands_without_a_gap(run_dir):
    """A unit security_props.json records nothing against keeps the M2 credit."""
    seed(run_dir, new_kinds_doc())
    L.cmd_ingest_wp([wp_report("flush", {}, loaded=[NK_CALL])])
    assert units()[cid("flush")]["evidence"][-1]["result"] == "wp_meta_simplified"
    assert L._meta_no_goal_credit_barred(units()[cid("flush")], L._meta_facts()) is None


@pytest.mark.unit
def test_eva_does_not_cover_a_unit_with_an_unchecked_site(run_dir):
    why = "an initializer call of send_frame: a macro hides the call"
    seed(run_dir, _with(new_kinds_doc(), NK_CALL, unchecked=[{**SITE, "reason": why}]))
    facts = L._meta_facts()
    assert L._eva_meta_cover_barred(units()[cid("flush")], facts)
    assert not L._eva_meta_cover_barred(units()[cid("resize")], facts)


@pytest.mark.unit
def test_in_code_checks_are_keyed_by_file_line_and_index(run_dir):
    second = {**PLACED, "property": "L5_sanitized_send_frame", "index": 1}
    write_json(Path("security_props.json"), {"code_checks": [PLACED, second]})
    checks = L._code_checks(Path("security_props.json"))
    assert set(checks) == {("prog.c", 12, 0), ("prog.c", 12, 1)}
    assert [c["property"] for c in L._code_lines(checks)[("prog.c", 12)]] == [NK_CALL, "L5_sanitized_send_frame"]


@pytest.mark.unit
def test_an_eva_row_of_a_line_with_two_checks_is_filed_under_both(run_dir):
    """Eva's report lists only open rows, so a lone row cannot be told apart by its position."""
    doc = new_kinds_doc()
    doc["obligations"]["prog.c#flush"].append(
        {"class": "l5_sanitized", "property": "L5_sanitized_send_frame", "reason": "sink"}
    )
    second = {**PLACED, "property": "L5_sanitized_send_frame", "index": 1}
    doc["code_checks"] = [PLACED, second]
    seed(run_dir, doc)
    state = units()
    row = {"file": "prog.c", "line": 12, "function": "flush", "kind": "user check", "annotation": "ready != 0"}
    lines = L._code_lines(L._code_checks())
    L._ingest_code_checks(state, [("unknown", row)], lines, NK_MODULE, "eva.json")
    for coverage_id in (cid("flush"), "prog.c#flush::l5_sanitized"):
        assert state[coverage_id]["evidence"][-1]["result"] == "eva_check_unknown", coverage_id


@pytest.mark.unit
def test_an_open_initializer_check_under_eva_keeps_the_unit_from_an_eva_cover(run_dir):
    """The statement call's instance is Valid under Eva, the initializer check Unknown: no Eva cover."""
    doc = _with(new_kinds_doc(), NK_CALL, init_checks=[INIT_CHECK])
    doc["code_checks"] = [PLACED]
    seed(run_dir, doc)
    state = units()
    section = {"instances": [{"instance": "prog.c#flush", "property": NK_CALL, "valid": 1}], "open_rows": []}
    row = {"file": "prog.c", "line": 12, "function": "flush", "kind": "user check", "annotation": "ready != 0"}
    touched: set[str] = set()
    L._ingest_eva_meta(
        state,
        {},
        section,
        NK_MODULE,
        {},
        "eva.json",
        {},
        touched,
        code_rows=[("unknown", row)],
        lines=L._code_lines(L._code_checks()),
    )
    assert state[cid("flush")]["bookkeeping"]["eva_verdicts"][NK_MODULE] == "unknown"


@pytest.mark.unit
def test_a_property_eva_did_not_load_keeps_its_unit_from_an_eva_cover(run_dir):
    """
    for_engine leaves a monotonic invariant out of Eva's meta file. A unit that holds it and a weak
    invariant whose checks are all Valid gets `none`, not `valid`: WP decides.
    """
    doc = new_kinds_doc()
    doc["obligations"]["prog.c#resize"].append(
        {"class": "l4_invariant", "property": "L4_invariant_phase_up", "reason": "monotonic"}
    )
    seed(run_dir, doc)
    state = units()
    section = {"instances": [{"instance": "prog.c#resize", "property": "L4_invariant_len_le_cap", "valid": 2}]}
    L._ingest_eva_meta(state, {}, section, NK_MODULE, {}, "eva.json", {}, set())
    assert state[cid("resize")]["bookkeeping"]["eva_verdicts"][NK_MODULE] == "none"


# ---------------------------------------------------------------------------------------------------
# Item 3a: in-code check goals carry their property's name
# ---------------------------------------------------------------------------------------------------


def _row(line: int, kind: str, prop: str, function: str = "f_init") -> dict:
    return {"file": "/w/prog.c", "line": line, "function": function, "kind": kind, "status": "Valid", "property": prop}


CHECKS_64 = [
    {"file": "prog.c", "line": 64, "function": "prog.c#f_init", "property": "L5_sanitized_net_send", "index": 0},
    {"file": "prog.c", "line": 64, "function": "prog.c#f_init", "property": "L6_no_leak_key", "index": 1},
]


@pytest.mark.unit
def test_the_checks_of_one_line_are_named_by_their_index():
    rows = [
        _row(63, "precondition", "\\valid(buf + (0 .. 7))"),
        _row(64, "user check", "\\initialized(&buf[0] + (0 .. 8 - 1))"),
        _row(64, "mem_access", "\\valid_read(buf)"),
        _row(64, "user check", "\\separated(&buf[0], &key)"),
    ]
    named, unnamed = rwf.code_check_rows(rows, CHECKS_64, "f_init")
    assert named == {1: "L5_sanitized_net_send", 3: "L6_no_leak_key"} and unnamed == []
    items = [{"kind": rows[i]["kind"], "annotation": f"{name}: {rows[i]['property']}"} for i, name in named.items()]
    assert [rwf.goal_obligation_class(i) for i in items] == ["l5_sanitized", "l6_no_leak"]
    # The index, not the list order, decides.
    named, _ = rwf.code_check_rows(rows, list(reversed(CHECKS_64)), "f_init")
    assert named == {1: "L5_sanitized_net_send", 3: "L6_no_leak_key"}


@pytest.mark.unit
def test_a_line_whose_check_rows_do_not_match_its_checks_stays_unnamed():
    """A third check on the line (a prover's own): the order no longer tells them apart."""
    rows = [_row(64, "user check", "a"), _row(64, "user check", "b"), _row(64, "user check", "c")]
    named, unnamed = rwf.code_check_rows(rows, CHECKS_64, "f_init")
    assert named == {} and unnamed == [{"line": 64, "checks": 2, "rows": 3}]
    # Rows of another function or another file are not counted.
    rows = [_row(64, "user check", "a"), _row(64, "user check", "b"), _row(64, "user check", "c", "g_init")]
    assert rwf.code_check_rows(rows, CHECKS_64, "f_init")[0] == {0: "L5_sanitized_net_send", 1: "L6_no_leak_key"}
    other = [{**_row(64, "user check", "a"), "file": "/w/other.c"}]
    assert rwf.code_check_rows(other, CHECKS_64, "f_init") == ({}, [{"line": 64, "checks": 2, "rows": 0}])


@pytest.mark.unit
def test_a_check_without_an_index_is_the_only_one_of_its_line():
    """The M6 and M7 checks (a wiped local, a gate's failure path) carry no index: one per line."""
    wiped = [{"file": "prog.c", "line": 26, "function": "prog.c#derive", "property": "L6_wiped_buf"}]
    rows = [_row(26, "user check", "\\forall integer i; ...", "derive")]
    assert rwf.code_check_rows(rows, wiped, "derive") == ({0: "L6_wiped_buf"}, [])


@pytest.mark.unit
def test_resolve_security_meta_returns_the_code_checks_of_the_function(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(rwf.SECURITY_PROPS_ENV, raising=False)
    wiped = {"file": "prog.c", "line": 26, "function": "prog.c#derive", "property": "L6_wiped_buf"}
    doc = {
        "properties": [{"name": "L6_wiped_buf", "acsl": "", "code": {"local": "buf"}, "instances": ["prog.c#derive"]}],
        "obligations": {"prog.c#derive": [{"class": "l6_wiped", "property": "L6_wiped_buf"}], "prog.c#other": []},
        "code_checks": [wiped, {**wiped, "function": "prog.c#other", "line": 40}],
    }
    write_json(tmp_path / "workspace/reports/security_props.json", doc)
    found = rwf.resolve_security_meta(None, Path("/w/prog.c"), "derive", tmp_path / "wp")
    assert found is not None and "meta_file" not in found and found["properties"] == []
    assert found["code_checks"] == [wiped]
    # A function with neither a property nor a check: nothing, as before.
    assert rwf.resolve_security_meta(None, Path("/w/prog.c"), "helper", tmp_path / "wp") is None


# ---------------------------------------------------------------------------------------------------
# Item 3b: MetAcsl's meta_annotate.ml line 675 failure
# ---------------------------------------------------------------------------------------------------

LOG_675 = (
    "[meta] Will process 1 properties\n"
    '  Raised at MetAcsl__Meta_annotate.writing_visitor#external_assigns.(fun) in file "meta_annotate.ml", '
    "line 675, characters 19-31\n"
    '[kernel] Unexpected error (File "meta_annotate.ml", line 675, characters 19-25: Assertion failed).\n'
    "  Please report as 'crash' at https://git.frama-c.com/pub/frama-c/issues\n"
)


@pytest.mark.unit
def test_the_set_valued_assigns_failure_is_recognised_with_the_callee(tmp_path):
    (tmp_path / "decls.h").write_text(
        "/*@ assigns {*a, *b}; */\nextern void pair(int *a, int *b);\n/*@ assigns *a; */\nvoid one(int *a);\n",
        encoding="utf-8",
    )
    src = tmp_path / "prog.c"
    src.write_text(
        '#include "decls.h"\n/*@ assigns \\union(*a, *b); */\nextern void two(int *a, int *b);\nvoid f(void) {}\n',
        encoding="utf-8",
    )
    found = rwf.metacsl_set_assigns_failure(LOG_675, [str(src)])
    assert found is not None and found["callees"] == ["pair", "two"]
    assert 'meta_annotate.ml", line 675' in found["message"] and "assigns" in found["cause"]
    assert rwf.metacsl_set_assigns_failure('[kernel] Unexpected error (File "other.ml", line 3)', [str(src)]) is None
    res = rwf._analysis_error_result("f", src, rwf.METACSL_SET_ASSIGNS, 125, {}, LOG_675)
    res["metacsl_failure"] = found
    hints = rwf.derive_wp_diagnostic_hints(res, LOG_675)
    assert "meta_annotate.ml" in hints[0] and "pair, two" in hints[0] and "Re-run once" not in " ".join(hints)


@pytest.mark.unit
def test_the_failure_without_a_readable_contract_still_names_the_cause(tmp_path):
    found = rwf.metacsl_set_assigns_failure(LOG_675, [str(tmp_path / "missing.c")])
    assert found is not None and found["callees"] == []
    res = rwf._analysis_error_result("f", tmp_path / "missing.c", rwf.METACSL_SET_ASSIGNS, 125, {}, LOG_675)
    res["metacsl_failure"] = found
    assert "set" in rwf.derive_wp_diagnostic_hints(res, LOG_675)[0]


# ---------------------------------------------------------------------------------------------------
# Item 4: a property whose `engines` exclude an engine never reaches it
# ---------------------------------------------------------------------------------------------------


def _engine_only(prop: dict, name: str, engines: list[str]) -> dict:
    """A copy of `prop` under another name, restricted to `engines` (as D1 writes a monotonic invariant)."""
    return {**prop, "name": name, "acsl": str(prop["acsl"]).replace(str(prop["name"]), name), "engines": engines}


@pytest.mark.unit
def test_eva_loads_only_the_properties_for_eva(meta_run):  # noqa: F811
    doc = props_doc()
    base = prop_of(doc, MB_AUTH_STATE)
    doc["properties"] += [
        _engine_only(base, "L4_invariant_phase_up", ["eacsl"]),
        _engine_only(base, "L4_invariant_for_eva", ["eva", "eacsl"]),
    ]
    section = static_section(doc)
    text = Path(section["meta_file"]).read_text(encoding="utf-8")
    assert "L4_invariant_phase_up" not in text and "L4_invariant_phase_up" not in section["properties"]
    assert "L4_invariant_phase_up" not in section["classes"] and "L4_invariant_phase_up" not in section["planned"]
    assert "L4_invariant_for_eva" in section["properties"] and "L4_invariant_for_eva" in text
    assert section["not_for_engine"] == ["L4_invariant_phase_up"]
    assert run_eva_slice.security_section([], section)["not_for_engine"] == ["L4_invariant_phase_up"]
    # Without such a property the section, its report and its cache digest are the ones they were.
    plain = static_section(props_doc())
    assert "not_for_engine" not in plain
    assert "not_for_engine" not in run_eva_slice.security_section([], plain)
    assert run_eva_slice._meta_digest({**plain, "not_for_engine": ["x"]}) == run_eva_slice._meta_digest(plain)


def _eacsl_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("prog.c", "prog.h"):
        dest = tmp_path / "workspace" / "work" / "src" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(META_EACSL_FIXTURE / name, dest)
    dest = tmp_path / "workspace" / "harnesses" / "harness_prog.c"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(META_EACSL_FIXTURE / "harness_prog.c", dest)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(fuzz_build.SECURITY_PROPS_ENV, raising=False)


@pytest.mark.unit
def test_the_fuzz_build_loads_only_the_properties_for_eacsl(tmp_path, monkeypatch):
    _eacsl_run(tmp_path, monkeypatch)
    doc = fixture_props(["eacsl"])
    base = doc["properties"][0]
    doc["properties"] += [
        _engine_only(base, "L4_invariant_eva_only", ["eva"]),
        _engine_only(base, "L4_invariant_phase_up", ["eacsl"]),
    ]
    write_props(EACSL_PROPS, doc)
    plan = fuzz_build.resolve_security_meta(None, EACSL_SOURCES, EACSL_OUT)
    assert plan is not None and plan["status"] == "loaded"
    assert plan["properties"] == [*ALL_PROPERTY_NAMES, "L4_invariant_phase_up"]
    assert "L4_invariant_eva_only" not in {p["name"] for p in plan["selected"]}
    assert plan["not_for_engine"] == ["L4_invariant_eva_only"]
    # Without such a property the plan is the one it was (no new key).
    write_props(EACSL_PROPS, fixture_props(["eacsl"]))
    plan = fuzz_build.resolve_security_meta(None, EACSL_SOURCES, EACSL_OUT)
    assert plan is not None
    assert "not_for_engine" not in plan


# ---------------------------------------------------------------------------------------------------
# Item 5: end to end in the image (FRAMAC_DOCKER_TESTS=1)
# ---------------------------------------------------------------------------------------------------

E2E_LISTS = {**INIT_LISTS, "auth_gates": [INIT_GATE], "invariants": [INIT_STRONG]}
E2E_FUNCTIONS = ("f_init", "g_init", "h_init")
# What the -DVIOLATE build breaks at each initializer (tests/fixtures/security_props/initializer/local_init.c).
E2E_BROKEN = {
    "f_init": {"L5_sanitized_net_send"},
    "g_init": {"L6_no_leak_key"},
    "h_init": {"L4_auth_state_login", "L4_invariant_auth_range"},
}
E2E_CLASS = {
    "L5_sanitized_net_send": "l5_sanitized",
    "L6_no_leak_key": "l6_no_leak",
    "L4_auth_state_login": "l4_auth_state",
    "L4_invariant_auth_range": "l4_invariant",
}


def _security_props_run(target: Path, run: Path) -> dict:
    """
    `security_props.py run` in the image, on the run's model and work tree, as the Makefile runs it.
    The model was built on the scratch volume's copy of the target (`/framac-scratch/tree`), where its
    trust record finds the threat model: the target is mounted there again.
    """
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{target.resolve()}:/framac-scratch/tree:ro", "-v", f"{run.resolve()}:/framac-run", "-w", "/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
        ANALYSIS_IMAGE, "-c", "timeout 600 python3 /opt/framac-pipeline/scripts/security_props.py run --work work",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads((run / "workspace/reports/security_props.json").read_text(encoding="utf-8"))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["satisfied", "violated"])
def test_initializer_calls_end_to_end_in_the_image(tmp_path, monkeypatch, violate):
    """
    Package E through the real pipeline: phase0_model.py (the dump's `initializer` flag),
    `security_props.py run` (the checks written into the work tree, `code_checks` with their
    `index`), run_wp_function.py (each check's goal named after its property) and `ledger.py
    ingest-wp`. On the -DVIOLATE build the unit of each broken property is not covered and its
    unproven goal carries the property's name and class; on the correct build every initializer
    function's units are covered by a proven check, never by `wp_meta_simplified`.
    """
    require_docker_images(ANALYSIS_IMAGE, BUILD_IMAGE)
    target = _one_file_target(tmp_path / "target", INIT_DIR / "local_init.c", E2E_LISTS, violate)
    run = tmp_path / "run"
    model = _model_with_initializer_flags(ROOT / "scripts", target, run)
    assert model["status"] == "ok"
    shutil.copytree(target, run / "work")
    doc = _security_props_run(target, run)
    assert not [w for w in doc["warnings"] if "initializers" in w or "schema" in w], doc["warnings"]
    placed = {f: [c for c in doc["code_checks"] if c["function"] == f"prog.c#{f}"] for f in E2E_FUNCTIONS}
    assert {f: sorted(c["property"] for c in cs) for f, cs in placed.items()} == {
        "f_init": ["L5_sanitized_net_send", "L6_no_leak_key"],
        "g_init": ["L5_sanitized_net_send", "L6_no_leak_key"],
        "h_init": ["L4_auth_state_login", "L4_invariant_auth_range"],
    }
    # h_init: one check before the declaration and one after it, on the same line.
    assert sorted(c["index"] for c in placed["h_init"]) == [0, 1] and len({c["line"] for c in placed["h_init"]}) == 1
    monkeypatch.chdir(run)
    _seed_one_file(run, model, doc)
    defs = " -DVIOLATE" if violate else ""
    for function in E2E_FUNCTIONS:
        report = _forward_wp(run / "work", run, function, defs)
        assert not report.get("security_props", {}).get("code_checks_unnamed"), report["security_props"]
        L.cmd_ingest_wp([run / f"workspace/reports/wp/{function}.json"])
        goals = [*report.get("layer_goals", []), *report.get("unproven_goals", [])]
        state = _ledger_units(run)
        for check in placed[function]:
            name, cls = check["property"], E2E_CLASS[check["property"]]
            mine = [
                g
                for g in goals
                if str(g.get("annotation") or "").startswith(f"{name}: ") and g["line"] == check["line"]
            ]
            detail = json.dumps({"goals": goals, "report": report.get("by_obligation_class")}, indent=1)[-4000:]
            assert len(mine) == 1 and mine[0]["obligation_class"] == cls, f"{function} {name}\n{detail}"
            unit = state[f"prog.c#{function}::{cls}"]
            if violate and name in E2E_BROKEN[function]:
                assert mine[0] in report["unproven_goals"], f"{function} {name}\n{detail}"
                assert unit["status"] != "covered", (function, name, unit)
            elif not violate:
                assert unit["status"] == "covered", (function, name, unit)
                assert unit["evidence"][-1]["result"] == "wp_proven", (function, name, unit["evidence"])
        if not violate:
            assert report["status"] == "all_proven", function
        for csv_path in (run / "workspace" / "wp").glob("*.csv"):
            csv_path.unlink()


@pytest.mark.integration
@pytest.mark.slow
def test_the_set_valued_assigns_failure_is_named_in_the_image(tmp_path):
    """
    callees/set_assigns.c with the \\writing property generated blind (its callers left in): MetAcsl
    stops at meta_annotate.ml line 675. The report says why and names the callee read from the
    contract, and tells no one to re-run.
    """
    require_docker_images(ANALYSIS_IMAGE)
    target = tmp_path / "target"
    target.mkdir()
    shutil.copy(FIX / "callees" / "set_assigns.c", target / "prog.c")
    run = tmp_path / "run"
    acsl = (
        "/*@ meta \\prop, \\name(L4_auth_state_login), \\targets(\\diff(\\ALL, {login})), \\context(\\writing),\n"
        "      \\separated(\\written, &auth_ok);\n*/"
    )
    prop = {
        "name": "L4_auth_state_login",
        "layer": 4,
        "kind": "auth_state",
        "obligation_class": "l4_auth_state",
        "acsl": acsl,
        "instances": ["prog.c#store", "prog.c#uses_two"],
        "sources": ["prog.c"],
        "notes": [],
    }
    write_json(run / "workspace/reports/security_props.json", {"preamble": "", "properties": [prop], "obligations": {}})
    report = _forward_wp(target, run, "store")
    assert report["status"] == "analysis_error" and report["reason"] == rwf.METACSL_SET_ASSIGNS, report.get("reason")
    assert report["metacsl_failure"]["callees"] == ["two"]
    assert "meta_annotate.ml" in report["diagnostic_hints"][0] and "Re-run once" not in " ".join(
        report["diagnostic_hints"]
    )
