"""
L5 on a wrapper sink (scripts/security_props.py, threat-model field `checked_at`): a declared sink that
completes its buffer itself and then hands it to other declared sinks (libmodbus `send_msg`: the TCP
length bytes are written by the backend's hook inside it) is checked where it hands the buffer over,
not where it is called.

The fixture `tests/fixtures/security_props/wrapper/` holds that shape (`l5_wrapper.c`: the hand-off is
a call through a function pointer whose type the backend's recv function shares) and its Phase 0
model, recorded from the analysis image (`wrapper_model.json`). The Docker-backed tests regenerate the
model and run MetAcsl, WP and Eva on it.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

import security_props as sp
import trust
from conftest import ANALYSIS_IMAGE, ROOT, write_json
from test_phase0_model import model_run  # noqa: F401  (Docker fixture)
from test_security_props import _ledger_units, _one_file_target, _seed_one_file, by_name, fn, model, threat

WRAPPER_DIR = ROOT / "tests" / "fixtures" / "security_props" / "wrapper"
WRAPPER = "prog.c#send_frame"
WRAPPER_PROP = "L5_sanitized_send_frame"
HANDOFF_LINE = 67
HANDOFF_CHECK = "/*@ check L5_sanitized_send_frame: \\initialized((msg) + (0 .. (msg_length) - 1)); */ "
TCP_SINK = {"function": "tcp_send", "kind": "network", "params": ["req"], "length": "req_length", "description": "d"}
RTU_SINK = {"function": "rtu_send", "kind": "network", "params": ["req"], "length": "req_length", "description": "d"}
PLAIN_SINK = {
    "function": "send_frame",
    "kind": "network",
    "params": ["msg"],
    "length": "msg_length",
    "description": "d",
}
CHECKED_AT_SINK = {**PLAIN_SINK, "checked_at": ["tcp_send", "rtu_send"]}
SEND_CANDIDATES = ["prog.c#rtu_recv", "prog.c#rtu_send", "prog.c#tcp_recv", "prog.c#tcp_send"]


def wrapper_model() -> dict:
    return json.loads((WRAPPER_DIR / "wrapper_model.json").read_text(encoding="utf-8"))


def wrapper_source() -> str:
    return (WRAPPER_DIR / "l5_wrapper.c").read_text(encoding="utf-8")


def wrapper_doc(*sinks: dict, m: dict | None = None) -> dict:
    return sp.generate(m or wrapper_model(), threat(output_sinks=list(sinks or (CHECKED_AT_SINK, TCP_SINK, RTU_SINK))))


def l5_properties(doc: dict, function: str) -> list[str]:
    return [o["property"] for o in doc["obligations"].get(function) or [] if o["class"] == "l5_sanitized"]


def assert_kept_at_callers(doc: dict, why: str) -> None:
    """The wrapper's property is where it was before `checked_at` existed, and the report says why."""
    prop = by_name(doc)[WRAPPER_PROP]
    assert prop["instances"] == ["prog.c#request_rtu", "prog.c#request_tcp"], prop
    assert "relocated" not in prop and "code" not in prop
    assert "\\context(\\calling)" in prop["acsl"] and "\\called == send_frame" in prop["acsl"]
    refused = [w for w in doc["warnings"] if w.startswith("wrapper sink send_frame: `checked_at` not applied")]
    assert len(refused) == 1 and why in refused[0], doc["warnings"]
    assert f"{WRAPPER_PROP} stays checked at the calls of send_frame" in refused[0]
    assert not sp.validate(doc)


# ---------------------------------------------------------------------------------------------------
# Regression: libmodbus run-1, `L5_sanitized_send_msg` false at twelve callers of `send_msg`
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_recorded_model_has_the_libmodbus_shape():
    m = wrapper_model()
    sites = {s["expr"]: s for s in m["indirect_sites"] if s["caller"] == WRAPPER}
    # The hand-off is a call through a pointer; its type match also names the recv functions.
    assert sites["(ctx->backend)->send"]["candidates"] == SEND_CANDIDATES
    assert sites["(ctx->backend)->send"]["loc"] == f"prog.c:{HANDOFF_LINE}"
    assert sites["(ctx->backend)->frame_pre"]["candidates"] == ["prog.c#rtu_frame_pre", "prog.c#tcp_frame_pre"]
    assert not [e for e in m["edges"] if e["caller"] == WRAPPER and e["kind"] == "direct"]
    assert wrapper_source().splitlines()[HANDOFF_LINE - 1] == "    rc = ctx->backend->send(ctx, msg, msg_length);"


@pytest.mark.unit
def test_a_wrapper_sink_is_checked_at_its_hand_off_not_at_its_callers(tmp_path):
    doc = wrapper_doc()
    assert not sp.validate(doc), sp.validate(doc)
    assert not [w for w in doc["warnings"] if "checked_at" in w], doc["warnings"]
    props = by_name(doc)
    prop = props[WRAPPER_PROP]
    # No instance at the callers any more: the frame is not complete there (the hook writes two bytes).
    assert prop["instances"] == [WRAPPER]
    assert l5_properties(doc, "prog.c#request_tcp") == [] and l5_properties(doc, "prog.c#request_rtu") == []
    assert l5_properties(doc, WRAPPER) == [WRAPPER_PROP]
    assert sp.meta_file_text(doc, "prog.c#request_tcp") is None
    # The move is recorded: where the property is not generated, where it is checked, on what evidence.
    moved = prop["relocated"]
    assert moved["wrapper"] == WRAPPER and moved["declared"] == ["tcp_send", "rtu_send"]
    assert moved["not_generated_at"] == ["prog.c#request_rtu", "prog.c#request_tcp"]
    assert moved["checked_at"] == [
        {
            "function": WRAPPER,
            "call": "(ctx->backend)->send",
            "loc": f"prog.c:{HANDOFF_LINE}",
            "kind": "indirect",
            "inner_sinks": ["rtu_send", "tcp_send"],
            "candidates": SEND_CANDIDATES,
        }
    ]
    assert moved["other_indirect_calls"] == [
        {
            "call": "(ctx->backend)->frame_pre",
            "loc": "prog.c:66",
            "candidates": ["prog.c#rtu_frame_pre", "prog.c#tcp_frame_pre"],
        }
    ]
    assert any("every function the call can dispatch to" in e for e in moved["evidence"]), moved["evidence"]
    assert any(n.startswith("a wrapper sink (threat model `checked_at`)") for n in prop["notes"]), prop["notes"]
    assert doc["summary"]["relocated"] == [WRAPPER_PROP]
    # MetAcsl cannot state the inner sinks' property at a call through a pointer: the in-code check
    # stands for their instance in the wrapper, and their direct callers keep theirs.
    assert moved["superseded"] == [
        {"property": "L5_sanitized_rtu_send", "function": WRAPPER},
        {"property": "L5_sanitized_tcp_send", "function": WRAPPER},
    ]
    assert WRAPPER not in props["L5_sanitized_tcp_send"]["instances"]
    assert "prog.c#ping" in props["L5_sanitized_tcp_send"]["instances"]
    # The check, written into the work tree before the hand-off, on the arguments of that call.
    assert prop["code"]["handoff"] == [{"callee": "send", "member": True, "args": [[1, 2]], "sites": 1}]
    assert sp.meta_file_text(doc, WRAPPER) is None
    work = tmp_path / "work"
    work.mkdir()
    (work / "prog.c").write_text(wrapper_source(), encoding="utf-8", newline="\n")
    out = sp.apply_taint(doc, work, taint=False)
    assert not out["skipped"], out["skipped"]
    assert out["code_checks"] == [
        {"file": "prog.c", "line": HANDOFF_LINE, "function": WRAPPER, "property": WRAPPER_PROP}
    ]
    assert out["handoffs"] == [{"function": WRAPPER, "property": WRAPPER_PROP, "callee": "send", "placed": 1}]
    lines = (work / "prog.c").read_text(encoding="utf-8").splitlines()
    assert lines[HANDOFF_LINE - 1] == "    " + HANDOFF_CHECK + "rc = ctx->backend->send(ctx, msg, msg_length);"
    assert len(lines) == len(wrapper_source().splitlines())
    # The call of the hook and the recv dispatch of another function (same pointer type) get no check.
    assert lines[HANDOFF_LINE - 2] == "    msg_length = ctx->backend->frame_pre(msg, msg_length);"
    assert sum("check L5_sanitized" in line for line in lines) == 1
    # The same plan again changes nothing; without the property the source is back.
    assert sp.apply_taint(doc, work, taint=False)["changed"] == []
    sp.apply_taint({"properties": []}, work)
    assert (work / "prog.c").read_text(encoding="utf-8") == wrapper_source()


@pytest.mark.unit
def test_the_brief_and_the_goal_class_of_a_hand_off_check():
    import run_wp_function as rwf

    doc = wrapper_doc()
    entry = sp.brief_entries(doc, "prog.c", "send_frame")[-1]
    assert entry["property"] == WRAPPER_PROP and entry["obligation_class"] == "l5_sanitized"
    assert "already in the code before each call that hands the buffer" in entry["discharge"]
    assert not [e for e in sp.brief_entries(doc, "prog.c", "request_tcp") if e["obligation_class"] == "l5_sanitized"]
    goal = {"kind": "check", "annotation": f"{WRAPPER_PROP}: \\initialized(msg + (0 .. msg_length - 1))"}
    assert rwf.goal_obligation_class(goal) == "l5_sanitized"


@pytest.mark.unit
def test_the_seed_keys_the_wrapper_unit_and_plans_none_for_its_callers(run_dir):
    m = wrapper_model()
    _seed_one_file(run_dir, m, wrapper_doc(m=m))
    units = _ledger_units(run_dir)
    assert units[f"{WRAPPER}::l5_sanitized"]["bookkeeping"]["security_properties"] == [WRAPPER_PROP]
    assert "prog.c#request_tcp::l5_sanitized" not in units and "prog.c#request_rtu::l5_sanitized" not in units
    assert units["prog.c#ping::l5_sanitized"]["bookkeeping"]["security_properties"] == ["L5_sanitized_tcp_send"]


@pytest.mark.unit
def test_the_threat_model_schema_takes_checked_at(tmp_path):
    target = _one_file_target(
        tmp_path / "t", WRAPPER_DIR / "l5_wrapper.c", {"output_sinks": [CHECKED_AT_SINK, TCP_SINK, RTU_SINK]}, False
    )
    loaded = trust.load_threat_model(target / "THREAT_MODEL.md")
    assert loaded["status"] == "ok", loaded
    bad = _one_file_target(
        tmp_path / "bad", WRAPPER_DIR / "l5_wrapper.c", {"output_sinks": [{**PLAIN_SINK, "checked_at": []}]}, False
    )
    assert trust.load_threat_model(bad / "THREAT_MODEL.md")["status"] == trust.STATUS_INVALID


# ---------------------------------------------------------------------------------------------------
# Controls: the property stays at the wrapper's callers
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_without_checked_at_nothing_moves():
    """A wrapper is never guessed: the same sinks without the field give the callers' property."""
    doc = wrapper_doc(PLAIN_SINK, TCP_SINK, RTU_SINK)
    props = by_name(doc)
    assert props[WRAPPER_PROP]["instances"] == ["prog.c#request_rtu", "prog.c#request_tcp"]
    assert "relocated" not in props[WRAPPER_PROP] and "relocated" not in doc["summary"]
    assert props["L5_sanitized_tcp_send"]["instances"] == ["prog.c#ping", "prog.c#poll_tcp", WRAPPER]
    assert not [w for w in doc["warnings"] if "checked_at" in w]


@pytest.mark.unit
def test_an_inner_call_that_is_not_a_declared_sink_keeps_the_property():
    # rtu_send is named but the threat model does not declare it: its backend would lose its check.
    assert_kept_at_callers(wrapper_doc(CHECKED_AT_SINK, TCP_SINK), "rtu_send is not a declared output sink")
    # Named, declared, but not a function the wrapper calls in the model.
    doc = wrapper_doc(
        {**PLAIN_SINK, "checked_at": ["tcp_send", "net_write"]},
        TCP_SINK,
        {"function": "net_write", "kind": "network", "params": ["buf"], "length": "n", "description": "d"},
    )
    assert_kept_at_callers(doc, "the model shows no call of net_write in send_frame")


@pytest.mark.unit
def test_an_unresolved_indirect_call_keeps_the_property():
    m = wrapper_model()
    # A call through a pointer the model could not resolve, as phase0_model.py records one.
    m["indirect_sites"].append(
        {
            "unit": "libprog.a",
            "units": ["libprog.a"],
            "caller": WRAPPER,
            "expr": "ctx->trace",
            "signature": "void(unsigned char *,int)",
            "loc": "prog.c:68",
            "candidates": [],
            "narrowing": "none",
            "narrowing_reason": "disabled",
            "dropped": [],
        }
    )
    assert_kept_at_callers(
        wrapper_doc(m=m), "a function-pointer call the model does not resolve (ctx->trace at prog.c:68)"
    )
    # A model that records no function-pointer call sites at all shows nothing about the wrapper.
    m = wrapper_model()
    del m["indirect_sites"]
    assert_kept_at_callers(wrapper_doc(m=m), "the model records no function-pointer call sites")


@pytest.mark.unit
def test_a_plain_declared_sink_is_unchanged():
    net = {"function": "net_write", "kind": "network", "params": ["buf"], "length": "n", "description": "d"}
    plain = by_name(wrapper_doc(net))["L5_sanitized_net_write"]
    assert plain["instances"] == ["prog.c#rtu_send", "prog.c#tcp_send"] and "relocated" not in plain
    # A sink the target only declares has no body to check a hand-off in.
    doc = wrapper_doc({**net, "checked_at": ["tcp_send"]}, TCP_SINK)
    asked = by_name(doc)["L5_sanitized_net_write"]
    assert asked["instances"] == plain["instances"] and asked["acsl"] == plain["acsl"] and "relocated" not in asked
    assert any("net_write is not defined in the build" in w for w in doc["warnings"]), doc["warnings"]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"kind": "log"}, "only a sink checked for initialized bytes"),
        ({"kind": "buffer"}, "only a sink checked for initialized bytes"),
        ({"checked_at": ["send_frame", "tcp_send"]}, "send_frame names itself"),
    ],
)
def test_what_checked_at_does_not_cover_is_refused(change, why):
    doc = wrapper_doc({**CHECKED_AT_SINK, **change}, TCP_SINK, RTU_SINK)
    assert any(w.startswith("wrapper sink send_frame: `checked_at` not applied") and why in w for w in doc["warnings"])
    assert "relocated" not in by_name(doc)[WRAPPER_PROP] and not sp.validate(doc)


@pytest.mark.unit
def test_a_wrapper_named_as_an_inner_sink_is_refused():
    doc = wrapper_doc(CHECKED_AT_SINK, {**TCP_SINK, "checked_at": ["rtu_send"]}, RTU_SINK)
    assert_kept_at_callers(doc, "tcp_send is a wrapper sink itself")


@pytest.mark.unit
def test_a_real_violation_still_has_an_instance_that_covers_it():
    """
    Uninitialized bytes reach an inner sink either through the wrapper, where the check before the
    hand-off covers every caller and every backend, or by a direct call, which keeps its MetAcsl instance.
    """
    doc = wrapper_doc()
    props = by_name(doc)
    assert props[WRAPPER_PROP]["instances"] == [WRAPPER]
    assert [c["candidates"] for c in props[WRAPPER_PROP]["relocated"]["checked_at"]] == [SEND_CANDIDATES]
    assert l5_properties(doc, "prog.c#ping") == ["L5_sanitized_tcp_send"]
    text, names, _ = sp.meta_file_text(doc, "prog.c#ping")
    assert names == ["L5_sanitized_tcp_send"] and "\\called == tcp_send" in text
    # Naming one backend only does not drop the other: the check is on the call, whatever it dispatches to.
    one = by_name(wrapper_doc({**PLAIN_SINK, "checked_at": ["tcp_send"]}, TCP_SINK, RTU_SINK))[WRAPPER_PROP]
    assert one["relocated"]["checked_at"][0]["candidates"] == SEND_CANDIDATES
    assert one["code"]["handoff"] == [{"callee": "send", "member": True, "args": [[1, 2]], "sites": 1}]


@pytest.mark.unit
def test_a_direct_hand_off_gets_the_check_too(tmp_path):
    source = (
        "void put(const unsigned char *b, int n);\n"
        "static void seal(unsigned char *b, int n) { b[n - 1] = 0; }\n"
        "void emit(unsigned char *b, int n)\n"
        "{\n"
        "    seal(b, n);\n"
        "    put(b, n);\n"
        "}\n"
    )
    formals = [{"name": "b", "kind": "pointer"}, {"name": "n", "kind": "value"}]
    m = model(
        {
            "e.c#emit": fn(
                "emit",
                "e.c",
                formals=formals,
                external_calls=["put"],
                call_sites=[{"callee": "put", "line": 6, "literals": {}}],
            ),
            "e.c#seal": fn("seal", "e.c", formals=formals),
            "e.c#user": fn("user", "e.c"),
        },
        edges=[("e.c#user", "e.c#emit"), ("e.c#emit", "e.c#seal")],
        external_formals={"put": [{"name": "b", "kind": "const_pointer"}, {"name": "n", "kind": "value"}]},
        indirect_sites=[],
    )
    sinks = [
        {"function": "emit", "kind": "file", "params": ["b"], "length": "n", "checked_at": ["put"], "description": "d"},
        {"function": "put", "kind": "file", "params": ["b"], "length": "n", "description": "d"},
    ]
    doc = sp.generate(m, threat(output_sinks=sinks))
    props = by_name(doc)
    assert not sp.validate(doc) and props["L5_sanitized_emit"]["instances"] == ["e.c#emit"], doc["warnings"]
    moved = props["L5_sanitized_emit"]["relocated"]
    assert moved["not_generated_at"] == ["e.c#user"] and moved["superseded"] == []
    assert moved["checked_at"] == [
        {"function": "e.c#emit", "call": "put", "loc": "e.c:6", "kind": "direct", "inner_sinks": ["put"]}
    ]
    # A direct call keeps the inner sink's MetAcsl instance in the wrapper as well.
    assert props["L5_sanitized_put"]["instances"] == ["e.c#emit"]
    work = tmp_path / "work"
    work.mkdir()
    (work / "e.c").write_text(source, encoding="utf-8", newline="\n")
    out = sp.apply_taint(doc, work, taint=False)
    assert out["handoffs"] == [{"function": "e.c#emit", "property": "L5_sanitized_emit", "callee": "put", "placed": 1}]
    assert (work / "e.c").read_text(encoding="utf-8").splitlines()[5] == (
        "    /*@ check L5_sanitized_emit: \\initialized((b) + (0 .. (n) - 1)); */ put(b, n);"
    )


@pytest.mark.unit
def test_a_hand_off_no_check_can_precede_keeps_the_property(run_dir, monkeypatch):
    """`run` moves the property only when the check is in the work tree before every hand-off call."""
    m = wrapper_model()
    m["trust"] = {}
    write_json(run_dir / "workspace/reports/phase0_model.json", m)
    monkeypatch.setattr(
        trust, "recorded_threat_model", lambda _m: (threat(output_sinks=[CHECKED_AT_SINK, TCP_SINK, RTU_SINK]), None)
    )
    work = run_dir / "workspace/work"
    work.mkdir(parents=True)
    # The hand-off inside a condition: an annotation cannot stand before it.
    source = wrapper_source().replace(
        "rc = ctx->backend->send(ctx, msg, msg_length);",
        "rc = 0; if (ctx->backend->send(ctx, msg, msg_length) < 0) rc = -1;",
    )
    assert source != wrapper_source()
    (work / "prog.c").write_text(source, encoding="utf-8", newline="\n")
    assert sp.main(["run"]) == 0
    doc = json.loads((run_dir / "workspace/reports/security_props.json").read_text(encoding="utf-8"))
    assert_kept_at_callers(doc, "the check could not be placed before every call that hands the buffer on (0 of 1")
    assert doc["code_checks"] == [] and (work / "prog.c").read_text(encoding="utf-8") == source
    # With the call a statement of its own, the same run moves the property and places the check.
    (work / "prog.c").write_text(wrapper_source(), encoding="utf-8", newline="\n")
    assert sp.main(["run"]) == 0
    doc = json.loads((run_dir / "workspace/reports/security_props.json").read_text(encoding="utf-8"))
    assert not sp.validate(doc) and by_name(doc)[WRAPPER_PROP]["instances"] == [WRAPPER], doc["warnings"]
    assert [(c["line"], c["property"]) for c in doc["code_checks"]] == [(HANDOFF_LINE, WRAPPER_PROP)]
    assert HANDOFF_CHECK in (work / "prog.c").read_text(encoding="utf-8").splitlines()[HANDOFF_LINE - 1]


# ---------------------------------------------------------------------------------------------------
# Acceptance (Docker): MetAcsl and WP before and after, Eva on the hand-off check
# ---------------------------------------------------------------------------------------------------


def _image_target(tmp_path, model_run, sinks: list[dict], violate: bool):  # noqa: F811
    """The fixture as a one-file target: its real model, its properties and its annotated work copy."""
    target = _one_file_target(tmp_path / "target", WRAPPER_DIR / "l5_wrapper.c", {"output_sinks": sinks}, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert not sp.validate(doc), sp.validate(doc)
    work = tmp_path / "work"
    work.mkdir()
    shutil.copy(target / "prog.c", work / "prog.c")
    applied = sp.apply_taint(doc, work, taint=False)
    assert not applied["skipped"], applied["skipped"]
    doc["code_checks"] = applied["code_checks"]
    write_json(run / "workspace/reports/security_props.json", doc)
    return m, doc, run, work


def _wp_report(run, work, function: str, violate: bool) -> dict:
    defs = " -DVIOLATE" if violate else ""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{work.resolve()}:/target:ro", "-v", f"{run.resolve()}:/framac-run", "-w", "/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        ANALYSIS_IMAGE, "-c",
        f"python3 /opt/framac-pipeline/scripts/run_wp_function.py --file /target/prog.c --function {function} "
        f"--out-dir workspace/wp '--cppflags=-I/target{defs}' --timeout 10 "
        f"--out-json workspace/reports/wp/{function}.json",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads((run / f"workspace/reports/wp/{function}.json").read_text(encoding="utf-8"))


def _goals(report: dict, name: str) -> tuple[list, list]:
    """(proven, unproven) goals of a WP report whose annotation carries the property name."""
    proven = [g for g in report["layer_goals"] if str(g.get("annotation") or "").startswith(f"{name}:")]
    unproven = [g for g in report["unproven_goals"] if str(g.get("annotation") or "").startswith(f"{name}:")]
    return proven, unproven


@pytest.mark.integration
@pytest.mark.slow
def test_the_callers_goal_is_false_before_and_gone_after_in_the_image(model_run, tmp_path):  # noqa: F811
    """
    libmodbus run-1 on a correct program. Before (no `checked_at`): MetAcsl asserts the wrapper's
    property in its caller, where two bytes are still unset, and WP cannot prove it. After: the caller
    has no such goal, and the wrapper holds the named check before its hand-off.
    """
    m, doc, run, work = _image_target(tmp_path / "before", model_run, [PLAIN_SINK, TCP_SINK, RTU_SINK], False)
    assert by_name(doc)[WRAPPER_PROP]["instances"] == ["prog.c#request_rtu", "prog.c#request_tcp"]
    before = _wp_report(run, work, "request_tcp", False)
    assert WRAPPER_PROP in before["security_props"]["properties"]
    proven, unproven = _goals(before, WRAPPER_PROP)
    assert unproven and not proven, json.dumps(before.get("wp_log_tail"), indent=1)

    m, doc, run, work = _image_target(tmp_path / "after", model_run, [CHECKED_AT_SINK, TCP_SINK, RTU_SINK], False)
    assert by_name(doc)[WRAPPER_PROP]["instances"] == [WRAPPER], doc["warnings"]
    after = _wp_report(run, work, "request_tcp", False)
    assert not (after.get("security_props") or {}).get("properties")
    assert _goals(after, WRAPPER_PROP) == ([], []) and "l5_sanitized" not in after["by_obligation_class"]
    # In the wrapper the check is a WP goal at the hand-off. WP does not prove it here: it cannot see
    # through the call of the hook without a `calls` clause; Eva and E-ACSL evaluate it (below).
    # Frama-C's report gives an in-code check without its name, and run_wp_function.py puts the name
    # back for meta-file goals only, so the goal is found by its place and predicate, not by its name.
    wrapper = _wp_report(run, work, "send_frame", False)
    goals = [
        g
        for g in wrapper["layer_goals"] + wrapper["unproven_goals"]
        if int(g.get("line") or 0) == HANDOFF_LINE and "check" in str(g.get("kind"))
    ]
    assert len(goals) == 1, json.dumps(wrapper.get("wp_log_tail"), indent=1)
    assert "\\initialized(msg + (0 .. msg_length - 1))" in goals[0]["annotation"], goals
    assert "Check 'L5_sanitized_send_frame'" in str(wrapper.get("wp_log_tail")), wrapper.get("wp_log_tail")


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["complete", "byte_unset"])
def test_the_hand_off_check_in_the_image(model_run, tmp_path, violate):  # noqa: F811
    """
    Eva decides the check before the hand-off on both backends: Valid when the hook completes the frame,
    not Valid when a caller leaves a byte unset that no hook writes. A direct call of an inner sink
    with an unset byte keeps an unproven MetAcsl goal.
    """
    m, doc, run, work = _image_target(tmp_path, model_run, [CHECKED_AT_SINK, TCP_SINK, RTU_SINK], violate)
    assert [c["line"] for c in doc["code_checks"]] == [HANDOFF_LINE]
    defs = " -cpp-extra-args=-DVIOLATE" if violate else ""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{work.resolve()}:/w", "-w", "/w", ANALYSIS_IMAGE, "-c",
        f"frama-c prog.c{defs} -eva -main run_both -then -report-csv out.csv",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    rows = [r.split("\t") for r in (work / "out.csv").read_text(encoding="utf-8").splitlines()]
    checks = [r[5] for r in rows if len(r) > 6 and r[3] == "send_frame" and "check" in r[4] and "initialized" in r[6]]
    assert len(checks) == 1, res.stdout
    assert (checks[0] == "Valid") is (not violate), (checks, res.stdout)
    ping = _wp_report(run, work, "ping", violate)
    proven, unproven = _goals(ping, "L5_sanitized_tcp_send")
    assert (bool(unproven), bool(proven)) == (violate, not violate), json.dumps(ping.get("wp_log_tail"), indent=1)
