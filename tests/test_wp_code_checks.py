r"""
WP and the properties security_props.py does not hand to MetAcsl, or MetAcsl cannot evaluate.

1. In-code checks (`code` properties: a local secret's wipe, a gate failure, the hand-off of a wrapper
   sink). Frama-C's report gives `/*@ check L5_sanitized_send_frame: ...; */` as a `user check` row with
   the predicate only, so run_wp_function.py classed it `rte` and no WP result could decide the
   property's unit. The name is read back from the source at the row's line.
2. A MetAcsl property on the calls of a function the parse lacks (libmodbus run-1: `send_msg` in
   modbus.c reaches `_modbus_tcp_send`, a static function of modbus-tcp.c, through
   `ctx->backend->send`). MetAcsl generates nothing and says nothing, which reads like "every instance
   decided statically"; `ledger.py ingest-wp` credited such a unit `wp_meta_simplified` on an
   `all_proven` report.

The logs and CSVs under tests/fixtures/security_props/code_checks/ are Frama-C's own output (34.0~beta,
framac-analysis:latest) for `run_wp_function.py --file <target> --function <fn> --timeout 10`, whole, and
the `*_props.json` beside them are the security_props.json of those runs (security_props.generate, then
apply_taint on the target, which is `*_prog.c`):
  local_*   tests/fixtures/security_props/local/l6_wiped_local.c, function `derive`
  after_*   tests/fixtures/security_props/wrapper/l5_wrapper.c with `checked_at`, function `send_frame`
  unseen_*  tests/fixtures/security_props/unseen_sink/relay.c, function `relay` (sink.c is not parsed)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import ledger as L
import run_wp_function as W
import test_security_props as tsp
import test_security_props_wrapper as tw
from conftest import write_json

pytestmark = pytest.mark.unit

CODE_CHECK_FIX = Path(__file__).resolve().parent / "fixtures" / "security_props" / "code_checks"
UNSEEN_SINK_DIR = Path(__file__).resolve().parent / "fixtures" / "security_props" / "unseen_sink"
CODE_CHECK_WORK = Path("workspace") / "work"
CODE_CHECK_PROPS = Path("workspace") / "reports" / "security_props.json"
LOCAL_CHECK_TEXT = (
    "/*@ check L6_wiped_buf: \\forall integer i; 0 <= i < sizeof(buf) / sizeof(buf[0]) ==> buf[i] == 0; */"
)


def _props(tag: str) -> dict:
    return json.loads((CODE_CHECK_FIX / f"{tag}_props.json").read_text(encoding="utf-8"))


def _stage(run: Path, tag: str, name: str = "prog.c", source: Path | None = None) -> Path:
    """The run's work tree with the target of capture `tag`, and its security_props.json; the source's path."""
    (run / CODE_CHECK_WORK).mkdir(parents=True, exist_ok=True)
    shutil.copy(source or CODE_CHECK_FIX / f"{tag}_prog.c", run / CODE_CHECK_WORK / name)
    write_json(run / CODE_CHECK_PROPS, _props(tag))
    return CODE_CHECK_WORK / name


def _replay(monkeypatch: pytest.MonkeyPatch, run: Path, record: str, c_file: Path, fn: str) -> tuple[dict, list]:
    """run_wp_function's report for the recorded Frama-C output `record`, and the commands it ran."""
    commands: list[list[str]] = []

    def fake(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        if "-wp" in cmd and "-report-csv" in cmd:
            shutil.copyfile(CODE_CHECK_FIX / f"{record}.csv", cmd[cmd.index("-report-csv") + 1])
            log = (CODE_CHECK_FIX / f"{record}.log").read_text(encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake)
    meta = W.resolve_security_meta(str(CODE_CHECK_PROPS), c_file, fn, run / "workspace" / "wp")
    res = W.run_wp_on_function(
        c_file,
        fn,
        run / "workspace" / "wp",
        cache_dir="off",
        retry_tail=False,
        retry_bitwise=False,
        retry_bytes=False,
        retry_cast_probe=False,
        security_meta=meta,
    )
    res = W.apply_verdict_limits(res, c_file, {"status": "consistent", "doomed": [], "dead_goals": 0})
    res["limits"]["guardrail_corpus"] = {"total": 2, "replayed": 2, "sampled": False, "empty": False}
    res["limits"]["dynamic_oracle"] = {"exercised": True, "hits": 4, "executed_inputs": 3}
    return res, commands


def _ingest(run: Path, report: dict) -> dict[str, dict]:
    path = run / "workspace" / "reports" / "wp" / f"{report['function']}.json"
    write_json(path, report)
    L.cmd_ingest_wp([path])
    return tsp._ledger_units(run)


def _local_model() -> dict:
    return tsp.model({"prog.c#derive": tsp.fn("derive", "prog.c", formals=[{"name": "n", "kind": "value"}])})


def _unseen_model() -> dict:
    """The Phase 0 facts of unseen_sink/: `relay` reaches `tcp_send` (sink.c) through a pointer only."""
    relay_formals = [
        {"name": "ctx", "kind": "pointer"},
        {"name": "msg", "kind": "const_pointer"},
        {"name": "msg_length", "kind": "value"},
    ]
    sink_formals = [
        {"name": "ctx", "kind": "pointer"},
        {"name": "req", "kind": "const_pointer"},
        {"name": "req_length", "kind": "value"},
    ]
    m = tsp.model(
        {
            "relay.c#relay": tsp.fn("relay", "relay.c", formals=relay_formals),
            "sink.c#tcp_send": tsp.fn("tcp_send", "sink.c", formals=sink_formals),
        }
    )
    m["edges"] = [
        {"caller": "relay.c#relay", "callee": "sink.c#tcp_send", "kind": "indirect", "sources": ["type-match"]}
    ]
    m["indirect_sites"] = [
        {
            "unit": "liba.a",
            "units": ["liba.a"],
            "caller": "relay.c#relay",
            "expr": "(ctx->backend)->send",
            "signature": "long(struct link *,unsigned char *,int)",
            "loc": "relay.c:27",
            "candidates": ["sink.c#tcp_send"],
            "narrowing": "none",
            "narrowing_reason": "disabled",
            "dropped": [],
        }
    ]
    return m


def _as_all_proven(report: dict) -> dict:
    """
    The report as it would read had every goal been proven. The recorded runs are not `all_proven`
    (no `terminates` clause, an indirect call without `calls`); only the fields that say so are changed
    here, the goals of the L4-L6 classes and `security_props` are Frama-C's.
    """
    out = json.loads(json.dumps(report))
    out["status"] = "all_proven"
    out["unproven_goals"] = []
    out["soundness"] = {**out.get("soundness", {}), "ok": True, "tier_b_unsound": []}
    for counts in out["by_obligation_class"].values():
        counts["unproven"] = 0
    return out


# ---------------------------------------------------------------------------------------------------
# In-code checks are goals of their property
# ---------------------------------------------------------------------------------------------------


def test_the_checks_of_a_local_secret_are_goals_of_its_wiped_property(run_dir, monkeypatch):
    c_file = _stage(run_dir, "local")
    res, commands = _replay(monkeypatch, run_dir, "local_derive", c_file, "derive")
    assert res["by_obligation_class"]["l6_wiped"] == {"proven": 2, "proven_under_hyp": 0, "unproven": 0}
    named = [g for g in res["layer_goals"] if g["obligation_class"] == "l6_wiped"]
    assert [(g["line"], g["kind"], g["status"]) for g in named] == [(26, "user check", "Valid")] * 1 + [
        (27, "user check", "Valid")
    ]
    assert all(g["annotation"].startswith("L6_wiped_buf: \\forall integer i;") for g in named)
    # Listed apart from the MetAcsl properties: nothing was loaded by MetAcsl, and no `-meta` stage ran.
    block = res["security_props"]
    assert block["properties"] == [] and block["code_properties"] == ["L6_wiped_buf"]
    assert block["code_checks"] == [{"line": 26, "property": "L6_wiped_buf"}, {"line": 27, "property": "L6_wiped_buf"}]
    assert block["code_checks_unnamed"] == [] and "code_line_names" not in block and "call_targets" not in block
    assert not any("-meta" in cmd for cmd in commands)
    # The predicate WP proved was read (from the row): the class is not "without a real clause".
    limits = res["limits"]
    assert limits["unchecked_layer_clauses"] == [] and limits["classes_without_real_clause"] == []


def test_the_ledger_can_decide_a_unit_keyed_on_an_in_code_check(run_dir, monkeypatch):
    c_file = _stage(run_dir, "local")
    tsp._seed_one_file(run_dir, _local_model(), _props("local"))
    unit = tsp._ledger_units(run_dir)["prog.c#derive::l6_wiped"]
    assert unit["status"] == "planned" and unit["bookkeeping"]["security_properties"] == ["L6_wiped_buf"]
    res, _ = _replay(monkeypatch, run_dir, "local_derive", c_file, "derive")
    # As recorded: the two checks are proven, the function is not (no `terminates` clause).
    assert res["status"] == "unproven_goals_remain"
    unit = _ingest(run_dir, res)["prog.c#derive::l6_wiped"]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == "wp_function_incomplete"
    unit = _ingest(run_dir, _as_all_proven(res))["prog.c#derive::l6_wiped"]
    assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_proven"
    assert unit["evidence"][-1]["summary"].startswith("2 goal(s) proven")


def test_the_hand_off_check_of_a_wrapper_is_an_unproven_goal_of_its_property(run_dir, monkeypatch):
    """libmodbus `send_msg`: the wrapper's unit is decided by the check before `ctx->backend->send`."""
    c_file = _stage(run_dir, "after")
    doc = _props("after")
    tsp._seed_one_file(run_dir, tw.wrapper_model(), doc)
    res, commands = _replay(monkeypatch, run_dir, "after_send_frame", c_file, "send_frame")
    assert res["by_obligation_class"]["l5_sanitized"] == {"proven": 0, "proven_under_hyp": 0, "unproven": 1}
    goal = next(g for g in res["unproven_goals"] if g["obligation_class"] == "l5_sanitized")
    assert (goal["line"], goal["kind"]) == (tw.HANDOFF_LINE, "user check")
    assert goal["annotation"] == "L5_sanitized_send_frame: \\initialized(msg + (0 .. msg_length - 1))"
    assert res["security_props"]["code_properties"] == [tw.WRAPPER_PROP] and not any("-meta" in c for c in commands)
    # No other row of the function took the name.
    assert sum("L5_sanitized" in str(g.get("annotation")) for g in res["unproven_goals"]) == 1
    unit = _ingest(run_dir, res)["prog.c#send_frame::l5_sanitized"]
    assert unit["status"] == "blocked" and unit["evidence"][-1]["result"] == "wp_unproven"
    assert unit["unresolved"] == [
        "unproven user check at line 67: L5_sanitized_send_frame: \\initialized(msg + (0 .. msg_length - 1))"
    ]


def test_a_check_is_found_where_the_provers_annotations_moved_it(tmp_path):
    """`code_checks` records the line at placement; a contract written above the function moves the check."""
    doc = _props("local")
    src = tmp_path / "prog.c"
    text = (CODE_CHECK_FIX / "local_prog.c").read_text(encoding="utf-8")
    moved = text.replace("int derive(int n)", "/*@ requires n >= 0;\n    assigns \\nothing;\n*/\nint derive(int n)")
    src.write_text(moved, encoding="utf-8", newline="\n")
    names, unnamed = W.code_check_names(doc, "prog.c#derive", src)
    assert names == {"29": "L6_wiped_buf", "30": "L6_wiped_buf"} and unnamed == []
    assert [c["line"] for c in doc["code_checks"]] == [26, 27]


def _edited(tmp_path: Path, old: str, new: str, count: int = 1) -> Path:
    text = (CODE_CHECK_FIX / "local_prog.c").read_text(encoding="utf-8")
    assert old in text
    src = tmp_path / "prog.c"
    src.write_text(text.replace(old, new, count), encoding="utf-8", newline="\n")
    return src


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        # A placed check deleted.
        (LOCAL_CHECK_TEXT + " return -1;", "return -1;", "2 check(s) placed, 1 `check L6_wiped_buf:` in the source"),
        # One more written by hand.
        ("return n;", "/*@ check L6_wiped_buf: \\true; */ return n;", "2 check(s) placed, 3 `check L6_wiped_buf:`"),
        # The predicate of a placed check weakened.
        ("==> buf[i] == 0; */ return -1;", "==> buf[i] >= 0; */ return -1;", "not the text security_props.py placed"),
    ],
)
def test_a_check_that_is_not_the_one_placed_names_no_goal(tmp_path, old, new, reason):
    names, unnamed = W.code_check_names(_props("local"), "prog.c#derive", _edited(tmp_path, old, new))
    assert names == {}
    assert len(unnamed) == 1 and unnamed[0]["property"] == "L6_wiped_buf" and reason in unnamed[0]["reason"]


def test_a_line_with_another_annotation_is_left_unnamed(tmp_path):
    """Two `user check` rows at one line cannot be told apart: neither takes the name."""
    src = _edited(tmp_path, LOCAL_CHECK_TEXT + " return -1;", LOCAL_CHECK_TEXT + " /*@ check \\true; */ return -1;")
    names, unnamed = W.code_check_names(_props("local"), "prog.c#derive", src)
    assert names == {"27": "L6_wiped_buf"}
    assert unnamed == [{"property": "L6_wiped_buf", "line": 26, "reason": "the line holds another annotation"}]


def test_a_check_the_report_does_not_record_as_placed_names_no_goal(tmp_path):
    doc = _props("local")
    doc["code_checks"] = []
    names, unnamed = W.code_check_names(doc, "prog.c#derive", CODE_CHECK_FIX / "local_prog.c")
    assert names == {} and "records no placed check" in unnamed[0]["reason"]
    # A function without a `code` property has nothing to name.
    assert W.code_check_names(_props("unseen"), "relay.c#relay", UNSEEN_SINK_DIR / "relay.c") == ({}, [])


def test_a_weakened_check_credits_nothing(run_dir, monkeypatch):
    """End to end: the rows are Frama-C's, the source no longer holds the check that was placed."""
    c_file = _stage(run_dir, "local")
    path = run_dir / c_file
    path.write_text(
        path.read_text(encoding="utf-8").replace("==> buf[i] == 0; */ return -1;", "==> buf[i] >= 0; */ return -1;"),
        encoding="utf-8",
        newline="\n",
    )
    tsp._seed_one_file(run_dir, _local_model(), _props("local"))
    res, _ = _replay(monkeypatch, run_dir, "local_derive", c_file, "derive")
    assert "l6_wiped" not in res["by_obligation_class"] and res["security_props"]["code_properties"] == []
    assert res["security_props"]["code_checks_unnamed"][0]["property"] == "L6_wiped_buf"
    unit = _ingest(run_dir, _as_all_proven(res))["prog.c#derive::l6_wiped"]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == "wp_no_credited_goals"


def test_a_trivial_in_code_check_is_no_real_clause():
    """Hand-built row: the shape `name_code_goal` gives a `user check` whose predicate is `\\true`."""
    goal = {"kind": "user check", "annotation": "L5_sanitized_send_frame: \\true", "obligation_class": "l5_sanitized"}
    limits = W.layer_clause_limits([{**goal, "file": "prog.c", "line": 67}], CODE_CHECK_FIX / "after_prog.c")
    assert limits["trivial_layer_clauses"] == ["L5_sanitized_send_frame"]
    assert limits["classes_without_real_clause"] == ["l5_sanitized"]


def test_a_hand_named_check_is_still_an_rte_goal(run_dir, monkeypatch):
    """Control: without a `code` property of the function, a `user check` row is never renamed."""
    c_file = _stage(run_dir, "local")
    doc = _props("local")
    doc["properties"][0]["instances"] = []
    doc["obligations"] = {}
    write_json(run_dir / CODE_CHECK_PROPS, doc)
    res, _ = _replay(monkeypatch, run_dir, "local_derive", c_file, "derive")
    assert "security_props" not in res and "l6_wiped" not in res["by_obligation_class"]
    # The two `check` rows, the five others, and two loop invariants (no l2_termination goal: "invariant" is no variant).
    assert res["by_obligation_class"]["rte"]["proven"] == 9


# ---------------------------------------------------------------------------------------------------
# A property on the calls of a function the parse lacks is not "decided statically"
# ---------------------------------------------------------------------------------------------------


def test_metacsl_generates_nothing_for_a_sink_the_parse_lacks_and_the_report_says_so(run_dir, monkeypatch):
    c_file = _stage(run_dir, "unseen", "relay.c", UNSEEN_SINK_DIR / "relay.c")
    res, commands = _replay(monkeypatch, run_dir, "unseen_relay", c_file, "relay")
    log = (CODE_CHECK_FIX / "unseen_relay.log").read_text(encoding="utf-8")
    # What Frama-C printed: one property processed, a successful translation, no goal of the class.
    assert "[meta] Will process 1 properties" in log and "[meta] Successful translation" in log
    assert any("-meta" in cmd for cmd in commands)
    block = res["security_props"]
    assert block["properties"] == ["L5_sanitized_tcp_send"] and block["extra_sources"] == []
    assert "l5_sanitized" not in res["by_obligation_class"]
    assert block["call_targets"] == {"L5_sanitized_tcp_send": {"function": "tcp_send", "seen": False}}


def test_a_unit_whose_sink_the_parse_lacks_is_not_credited_as_decided_statically(run_dir, monkeypatch):
    c_file = _stage(run_dir, "unseen", "relay.c", UNSEEN_SINK_DIR / "relay.c")
    tsp._seed_one_file(run_dir, _unseen_model(), _props("unseen"))
    unit = tsp._ledger_units(run_dir)["relay.c#relay::l5_sanitized"]
    assert unit["bookkeeping"]["security_properties"] == ["L5_sanitized_tcp_send"]
    res, _ = _replay(monkeypatch, run_dir, "unseen_relay", c_file, "relay")
    # As recorded the run is `unsound_proof` (an indirect call without `calls`): never credited.
    assert res["status"] == "unsound_proof"
    unit = _ingest(run_dir, _as_all_proven(res))["relay.c#relay::l5_sanitized"]
    assert unit["status"] == "planned"
    last = unit["evidence"][-1]
    assert last["result"] == "wp_meta_not_evaluated" and last["discharging"] is False
    assert "MetAcsl generated no instance of L5_sanitized_tcp_send (on the calls of tcp_send)" in last["summary"]


def _session_report(block: dict, counts: dict | None = None) -> dict:
    report = json.loads((tsp.FIX / "wp_close_wiped.json").read_text(encoding="utf-8"))
    by_class = {"rte": {"proven": 1, "proven_under_hyp": 0, "unproven": 0}}
    if counts:
        by_class["l6_no_leak"] = counts
    report.update(function="session_admin", by_obligation_class=by_class, layer_goals=[], security_props=block)
    report["limits"]["unchecked_layer_clauses"] = []
    return report


@pytest.mark.parametrize(
    ("targets", "counts", "result", "status"),
    [
        # The sink is in the parse and no goal is left: MetAcsl decided the instances.
        ({"L6_no_leak_session_key": {"function": "log_line", "seen": True}}, None, "wp_meta_simplified", "covered"),
        # A property that is not stated on a call (a write, a read) has no entry.
        ({}, None, "wp_meta_simplified", "covered"),
        ({"L6_no_leak_session_key": {"function": "log_line", "seen": False}}, None, "wp_meta_not_evaluated", "planned"),
        # A report written before the field existed shows nothing about the parse.
        (None, None, "wp_meta_not_evaluated", "planned"),
        # Proven goals of the class do not make up for a property whose sink was not seen.
        (
            {"L6_no_leak_session_key": {"function": "log_line", "seen": False}},
            {"proven": 1, "proven_under_hyp": 0, "unproven": 0},
            "wp_meta_not_evaluated",
            "planned",
        ),
        # With goals, a report without the field is credited as before.
        (None, {"proven": 1, "proven_under_hyp": 0, "unproven": 0}, "wp_proven", "covered"),
    ],
)
def test_the_credit_of_a_metacsl_unit_follows_what_the_report_shows_of_the_parse(
    run_dir, targets, counts, result, status
):
    """Hand-built `security_props` blocks on the recorded session report (tests/test_security_props.py)."""
    tsp._seed_sinks(run_dir)
    block: dict = {"props": "workspace/reports/security_props.json", "properties": ["L6_no_leak_session_key"]}
    if targets is not None:
        block["call_targets"] = targets
    units = _ingest(run_dir, _session_report(block, counts))
    leak = units["session.c#session_admin::l6_no_leak"]
    assert (leak["evidence"][-1]["result"], leak["status"]) == (result, status)


def test_a_name_is_seen_in_code_only():
    before = tw.wrapper_doc(tw.PLAIN_SINK, tw.TCP_SINK, tw.RTU_SINK)
    names = ["L5_sanitized_tcp_send", "L5_sanitized_rtu_send", "L5_sanitized_send_frame"]
    seen = W.call_targets(before, names, [tw.WRAPPER_DIR / "l5_wrapper.c"])
    # send_frame forwards to the two others: it has no MetAcsl text, so nothing is stated on its calls.
    assert seen == {
        "L5_sanitized_tcp_send": {"function": "tcp_send", "seen": True},
        "L5_sanitized_rtu_send": {"function": "rtu_send", "seen": True},
    }
    # relay.c names `tcp_send` in a comment, and has a member `send`: neither is the function.
    relay = (UNSEEN_SINK_DIR / "relay.c").read_text(encoding="utf-8")
    assert "`tcp_send`, sink.c" in relay and "->send(" in relay
    unseen = _props("unseen")
    assert W.call_targets(unseen, ["L5_sanitized_tcp_send"], [UNSEEN_SINK_DIR / "relay.c"]) == {
        "L5_sanitized_tcp_send": {"function": "tcp_send", "seen": False}
    }
    # With the file that defines it handed to Frama-C too, it is seen; a property that was not loaded is not listed.
    both = [UNSEEN_SINK_DIR / "relay.c", UNSEEN_SINK_DIR / "sink.c"]
    assert W.call_targets(unseen, ["L5_sanitized_tcp_send"], both)["L5_sanitized_tcp_send"]["seen"] is True
    assert W.call_targets(unseen, [], both) == {}


def test_a_precondition_on_a_sink_the_parse_lacks_is_not_decided_statically():
    """
    A sink called through a pointer carries its property as a precondition (`entry`): when the file that
    defines it is not parsed, MetAcsl generates nothing there either, and the run looks decided.
    """
    acsl = (
        "/*@ meta \\prop, \\name(L5_sanitized_tcp_send), \\targets({tcp_send}), \\context(\\precond),\n"
        "      \\fguard(\\initialized(\\formal(req) + (0 .. \\formal(req_length) - 1)));\n*/"
    )
    doc = {"properties": [{"name": "L5_sanitized_tcp_send", "acsl": acsl}]}
    relay = UNSEEN_SINK_DIR / "relay.c"
    assert W.call_targets(doc, ["L5_sanitized_tcp_send"], [relay]) == {
        "L5_sanitized_tcp_send": {"function": "tcp_send", "seen": False}
    }
    both = [relay, UNSEEN_SINK_DIR / "sink.c"]
    assert W.call_targets(doc, ["L5_sanitized_tcp_send"], both)["L5_sanitized_tcp_send"]["seen"] is True
    # Several targets name no one function the property depends on.
    several = {"properties": [{"name": "P", "acsl": acsl.replace("{tcp_send}", "{tcp_send, rtu_send}")}]}
    assert W.call_targets(several, ["P"], [relay]) == {}
