"""
Security layers via MetAcsl (docs/plans/archive/phase0-implementation-plan.md step I9): property generation from the
threat model (scripts/security_props.py), the meta file of a WP run and its goal names
(run_wp_function.py), the ledger classes (ledger.py seed / ingest-wp) and the Phase 3 brief entries.

The fixture `tests/fixtures/security_props/` holds one session library in two versions: its key is
never wiped (`secret_unwiped`) or wiped (`secret_wiped`). Its Phase 0 model and the WP reports of
`session_close` are recorded; the Docker-backed test regenerates them and checks the acceptance:
the unwiped key leaves the L6 unit unproven, the wipe proves it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

import ledger as L
import run_wp_function as rwf
import security_props as sp
import trust
from acsl_ast import tokenize_c_acsl
from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images, wp_proved_goals, write_json
from test_phase0_model import model_run  # noqa: F401  (Docker fixture)

FIX = ROOT / "tests" / "fixtures" / "security_props"
ASSETS = ROOT / "benchmark" / "assets"


def session_model() -> dict:
    return json.loads((FIX / "session_model.json").read_text(encoding="utf-8"))


def session_props() -> dict:
    return sp.generate(session_model(), trust.load_threat_model(FIX / "secret_unwiped" / "THREAT_MODEL.md"))


def by_name(doc: dict) -> dict[str, dict]:
    return {p["name"]: p for p in doc["properties"]}


def fn(name: str, file: str = "a.c", **extra) -> dict:
    rec = {"name": name, "file": file, "units": ["liba.a"], "source": "frama-c-kernel", "external_calls": []}
    rec.update(extra)
    return rec


def model(functions: dict, edges=(), **extra) -> dict:
    out = {
        "status": "ok",
        "units": {"liba.a": {"kind": "static_lib", "test": False}},
        "functions": functions,
        "edges": [{"caller": a, "callee": b, "kind": "direct"} for a, b in edges],
    }
    out.update(extra)
    return out


def threat(**lists) -> dict:
    block = {"schema_version": 1, "input_sources": [], "secrets": [], "auth_gates": [], "output_sinks": []}
    block.update(lists)
    return {"status": "ok", "block": block}


# ---------------------------------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_session_fixture_properties_and_instances():
    doc = session_props()
    assert not sp.validate(doc) and doc["warnings"] == []
    props = by_name(doc)
    assert set(props) == {
        "L4_auth_state_session_login",
        "L4_auth_required_session_login",
        "L5_sanitized_log_line",
        "L6_wiped_session_key",
        "L6_no_leak_session_key",
    }
    # Only the gate may write auth_ok: the other direct writer and the pointer writer hold assertions.
    assert props["L4_auth_state_session_login"]["instances"] == [
        "session.c#session_copy_state",
        "session.c#session_reset",
    ]
    assert props["L4_auth_state_session_login"]["direct_writers"] == ["session.c#session_reset"]
    assert "\\separated(\\written, &auth_ok)" in props["L4_auth_state_session_login"]["acsl"]
    # The privileged function's precondition is proved where it is called.
    assert props["L4_auth_required_session_login"]["instances"] == ["session.c#session_dispatch"]
    # The log sink is external: its writers (callers) discharge the check. session_admin hands it a
    # string literal only, decided from the model (plan step M2): no goal there.
    assert props["L5_sanitized_log_line"]["instances"] == ["session.c#session_status"]
    assert props["L5_sanitized_log_line"]["decided"] == [
        {
            "function": "session.c#session_admin",
            "verdict": "satisfied",
            "how": "syntactic",
            "reason": "every call of log_line passes string literals without CR or LF (line(s) 25)",
        }
    ]
    assert {"decided": "satisfied", "class": "l5_sanitized"}.items() <= next(
        o for o in doc["obligations"]["session.c#session_admin"] if o["class"] == "l5_sanitized"
    ).items()
    assert "no_crlf_string(\\called_arg(msg))" in props["L5_sanitized_log_line"]["acsl"]
    wiped = props["L6_wiped_session_key"]
    assert wiped["instances"] == ["session.c#session_close"] and wiped["sources"] == ["session.c"]
    assert "sizeof(session_key) / sizeof(session_key[0])" in wiped["acsl"]
    assert "\\separated(\\called_arg(msg), &session_key)" in props["L6_no_leak_session_key"]["acsl"]
    # L3: the one function writing through a pointer.
    assert doc["frame"] == [{"function": "session.c#session_copy_state", "reason": "writes through parameter(s) out"}]
    classes = {c["class"] for c in doc["obligations"]["session.c#session_copy_state"]}
    assert classes == {"l3_frame", "l4_auth_state"}
    assert doc["summary"]["functions_by_class"]["l6_wiped"] == 1


@pytest.mark.unit
def test_generated_annotations_are_pure_acsl():
    doc = session_props()
    for text in [doc["preamble"], *(p["acsl"] for p in doc["properties"])]:
        tokens = tokenize_c_acsl(text)
        assert [t for t in tokens if t.kind not in ("whitespace", "acsl_block", "acsl_line", "c_comment")] == []
    # The meta file's one directive, above the preamble: libc's `strlen` for no_crlf_string (S8).
    found = sp.meta_file_text(doc, "session.c#session_status")
    assert found is not None and found[0].startswith(sp.META_INCLUDE + "\n")


def _acsl_definition(text: str, name: str) -> str | None:
    """The whitespace-normalized text of `predicate <name>(...) = ...;` in an ACSL block, or None."""
    m = re.search(r"predicate\s+" + re.escape(name) + r"\s*\([^)]*\)\s*=[\s\S]*?;[ \t]*\n", text + "\n")
    return " ".join(m.group(0).split()) if m else None


@pytest.mark.unit
def test_preamble_repeats_the_vocabulary_text():
    """S8: the meta file's no_crlf_string is the vocabulary's, word for word, so Frama-C merges the two."""
    preamble = sp.load_template("preamble")["preamble"]
    mine = _acsl_definition(preamble, "no_crlf_string")
    assert (
        mine
        == "predicate no_crlf_string(char *s) = \\forall integer i; 0 <= i < strlen(s) ==> (s[i] != '\\r' && s[i] != '\\n');"
    )
    vocabulary = (ROOT / "templates" / "acsl" / "acsl_vocabulary.h").read_text(encoding="utf-8")
    theirs = _acsl_definition(vocabulary, "no_crlf_string")
    if theirs is not None:  # the libc track's S8 adds it to the vocabulary
        assert mine == theirs
    for template in ("l4_auth_required", "l4_auth_state", "l5_sanitized", "l6_no_leak", "l6_wiped"):
        assert not re.search(r"\b(?:predicate|logic)\s+\w+\s*\(", "".join(sp.load_template(template).values())), (
            template
        )


@pytest.mark.unit
def test_without_a_threat_model_only_frames():
    doc = sp.generate(session_model(), {"status": "no_threat_model"})
    assert doc["properties"] == [] and doc["threat_model"]["status"] == "no_threat_model"
    assert [f["function"] for f in doc["frame"]] == ["session.c#session_copy_state"]
    invalid = sp.generate(session_model(), {"status": "invalid_threat_model"})
    assert any("invalid threat model" in w for w in invalid["warnings"])


@pytest.mark.unit
def test_frame_rule_libc_writers_and_models_without_write_facts():
    m = model(
        {
            "a.c#copy": fn("copy", external_calls=["memcpy"], writes={"pointer": 0, "params": [], "globals": []}),
            "a.c#pure": fn("pure", writes={"pointer": 0, "params": [], "globals": ["g"]}),
        }
    )
    doc = sp.generate(m, None)
    assert doc["frame"] == [{"function": "a.c#copy", "reason": "calls memcpy"}]
    old = model({"a.c#f": fn("f", signature="void(int *)"), "a.c#g": fn("g", signature="int(int)")})
    doc = sp.generate(old, None)
    assert [f["function"] for f in doc["frame"]] == ["a.c#f"]
    assert any("no write facts" in w for w in doc["warnings"])


@pytest.mark.unit
def test_parameter_and_field_secrets_and_a_formal_auth_state():
    m = model(
        {
            "a.c#derive": fn("derive", formals=[{"name": "key", "kind": "pointer"}, {"name": "len", "kind": "value"}]),
            "a.c#ctx_free": fn("ctx_free", formals=[{"name": "ctx", "kind": "pointer"}]),
            "a.c#check": fn(
                "check",
                formals=[{"name": "s", "kind": "pointer"}],
                writes={"pointer": 1, "params": ["s"], "globals": []},
            ),
            "a.c#act": fn("act", formals=[{"name": "s", "kind": "pointer"}]),
        },
        edges=[("a.c#derive", "a.c#act")],
        external_formals={
            "send": [
                {"name": "fd", "kind": "value"},
                {"name": "buf", "kind": "const_pointer"},
                {"name": "n", "kind": "value"},
            ]
        },
    )
    m["functions"]["a.c#derive"]["external_calls"] = ["send"]
    doc = sp.generate(
        m,
        threat(
            secrets=[
                {"name": "key", "kind": "parameter", "function": "derive", "size": "len", "description": "d"},
                {"name": "secret", "kind": "field", "object": "ctx", "function": "ctx_free", "description": "d"},
                {"name": "token", "kind": "return", "function": "derive", "description": "d"},
            ],
            auth_gates=[{"function": "check", "state": "s->ok", "protects": ["act"], "description": "d"}],
            output_sinks=[{"function": "send", "kind": "network", "length": "n", "description": "d"}],
        ),
    )
    assert not sp.validate(doc)
    props = by_name(doc)
    assert "0 <= i < \\formal(len) ==> \\formal(key)[i] == 0" in props["L6_wiped_key"]["acsl"]
    # A parameter secret: checked at the sink calls of its own function only.
    leak = props["L6_no_leak_key"]
    assert leak["instances"] == ["a.c#derive"] and "\\targets({derive})" in leak["acsl"]
    assert "\\separated(\\called_arg(buf), \\formal(key) + (0 .. \\formal(len) - 1))" in leak["acsl"]
    assert "\\formal(ctx)->secret" in props["L6_wiped_secret"]["acsl"]
    # Bytes handed to a network sink are initialized, over its length parameter.
    assert "\\initialized(\\called_arg(buf) + (0 .. \\called_arg(n) - 1))" in props["L5_sanitized_send"]["acsl"]
    # A state reached from a parameter: guarded forms.
    assert "\\tguard(\\separated(\\written, &\\formal(s)->ok))" in props["L4_auth_state_check"]["acsl"]
    assert "\\fguard(\\formal(s)->ok != 0)" in props["L4_auth_required_check"]["acsl"]
    # `act` is called by derive; the gate itself is not an instance of its own state property.
    assert props["L4_auth_required_check"]["instances"] == ["a.c#derive"]
    assert "a.c#check" not in props["L4_auth_state_check"]["instances"]
    assert any("kind `return`" in w for w in doc["warnings"])


@pytest.mark.unit
def test_unusable_items_warn_instead_of_guessing():
    m = model({"a.c#g": fn("g"), "a.c#p": fn("p")})
    doc = sp.generate(
        m,
        threat(
            auth_gates=[
                {"function": "g", "protects": ["p"], "description": "d"},
                {"function": "g", "state": "nowhere", "protects": ["p"], "description": "d"},
            ],
            secrets=[{"name": "k", "kind": "global", "description": "d"}],
            output_sinks=[{"function": "missing", "kind": "log", "description": "d"}],
        ),
    )
    assert doc["properties"] == []
    text = " ".join(doc["warnings"])
    assert "no `state`" in text and "nowhere" in text and "secret k" in text and "missing" in text


@pytest.mark.unit
def test_benchmark_threat_models_produce_properties():
    """QCBOR's buffer sink gives an L5 postcondition on its out-parameter; minmea and x509-parser declare
    no secret, gate or sink, so they get frames only."""
    qcbor = model(
        {
            "src/qcbor_main_encode.c#QCBOREncode_Finish": fn(
                "QCBOREncode_Finish",
                "src/qcbor_main_encode.c",
                formals=[{"name": "pMe", "kind": "pointer"}, {"name": "pEncodedCBOR", "kind": "pointer"}],
                writes={"pointer": 2, "params": ["pEncodedCBOR", "pMe"], "globals": []},
            ),
        }
    )
    doc = sp.generate(qcbor, trust.load_threat_model(ASSETS / "qcbor" / "THREAT_MODEL.md"))
    props = by_name(doc)
    assert list(props) == ["L5_sanitized_QCBOREncode_Finish"]
    assert "\\context(\\postcond)" in props["L5_sanitized_QCBOREncode_Finish"]["acsl"]
    assert "\\initialized(\\formal(pEncodedCBOR))" in props["L5_sanitized_QCBOREncode_Finish"]["acsl"]
    for target in ("minmea", "x509-parser"):
        threat_model = trust.load_threat_model(ASSETS / target / "THREAT_MODEL.md")
        assert threat_model["status"] == "ok"
        assert sp.generate(qcbor, threat_model)["properties"] == []


# ---------------------------------------------------------------------------------------------------
# Meta file and WP goals
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_meta_file_lines_and_function_match(tmp_path):
    doc = session_props()
    meta = sp.meta_file_text(doc, "session.c#session_status")
    assert meta is not None
    text, names, sources = meta
    assert names == ["L5_sanitized_log_line", "L6_no_leak_session_key"] and sources == ["session.c"]
    # The preamble is guarded: the force-included vocabulary already declares what it repeats.
    guard_open, guard_close = sp.META_PREAMBLE_GUARD
    assert text.startswith(f"{sp.META_INCLUDE}\n{guard_open}\n{doc['preamble']}\n{guard_close}\n")
    lines = sp.meta_line_names(text)
    assert set(lines.values()) == {"L5_sanitized_log_line", "L6_no_leak_session_key"}
    first = min(k for k, v in lines.items() if v == "L6_no_leak_session_key")
    assert "L6_no_leak_session_key" in text.splitlines()[first - 1]
    assert sp.meta_file_text(doc, "session.c#session_login") is None
    assert sp.match_function(doc, "agents/a1/scratch/work/session.c", "session_close") == (
        "session.c#session_close",
        "agents/a1/scratch/work/",
    )
    assert sp.match_function(doc, "/target/other.c", "session_close") is None
    out = tmp_path / "m.c"
    assert (
        sp.main(
            [
                "meta-file",
                "--props",
                str(_write(tmp_path / "p.json", doc)),
                "--function",
                "session.c#session_close",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert "L6_wiped_session_key" in out.read_text(encoding="utf-8")


@pytest.mark.unit
def test_module_meta_file_holds_every_property_with_an_instance():
    """The whole-module meta file (Eva, E-ACSL): same layout as a function's, all MetAcsl properties."""
    doc = session_props()
    meta = sp.module_meta_file_text(doc)
    assert meta is not None
    text, names, sources = meta
    with_instances = [p["name"] for p in doc["properties"] if p["instances"] and not p.get("code")]
    assert names == with_instances and len(names) > 2
    guard_open, guard_close = sp.META_PREAMBLE_GUARD
    assert text.startswith(f"{sp.META_INCLUDE}\n{guard_open}\n{doc['preamble']}\n{guard_close}\n")
    assert set(sp.meta_line_names(text).values()) == set(names)
    assert sources == sorted({s for p in doc["properties"] if p["name"] in names for s in p["sources"]})
    # Restricted to some functions, it is those functions' properties; one function gives its WP file.
    one = sp.module_meta_file_text(doc, ["session.c#session_status"])
    assert one == sp.meta_file_text(doc, "session.c#session_status")
    assert sp.module_meta_file_text(doc, ["session.c#session_login"]) is None
    # A property without an instance (decided from the model) or written into the work tree has no goal.
    bare = {"preamble": "", "properties": [{"name": "A", "acsl": "/* a */", "instances": []}]}
    assert sp.module_meta_file_text(bare) is None
    in_code = {"name": "B", "acsl": "", "code": {"op": "local"}, "instances": ["f.c#f"]}
    assert sp.module_meta_file_text({"preamble": "", "properties": [in_code]}) is None


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.unit
def test_wp_goal_classes_for_generated_names():
    cls = rwf.goal_obligation_class
    assert cls({"kind": "postcondition", "annotation": "L6_wiped_k: meta: \\forall integer i; ..."}) == "l6_wiped"
    assert cls({"kind": "user assertion", "annotation": "L6_no_leak_k: meta: \\separated(p, &k)"}) == "l6_no_leak"
    assert cls({"kind": "precondition", "annotation": "L4_auth_required_g: meta: ok != 0"}) == "l4_auth_required"
    assert (
        cls({"kind": "user assertion", "annotation": "L4_auth_state_g: meta: \\separated(p, &ok)"}) == "l4_auth_state"
    )
    assert cls({"kind": "user assertion", "annotation": "L5_sanitized_log: meta: L5_no_crlf(m)"}) == "l5_sanitized"
    # A prover's own named clause is classed by its kind (D8: the pre-I9 layer classes are gone).
    assert cls({"kind": "postcondition", "annotation": "L6_zeroed: buffer_is_zeroed(k, 16)"}) == "rte"


@pytest.mark.unit
def test_report_assertions_get_their_property_name_back(tmp_path, monkeypatch):
    props = _write(tmp_path / "workspace" / "reports" / "security_props.json", session_props())
    monkeypatch.chdir(tmp_path)
    meta = rwf.resolve_security_meta(None, Path("/target/session.c"), "session_reset", tmp_path / "wp")
    assert meta is not None and meta["properties"] == ["L4_auth_state_session_login"]
    assert meta["props"] == str(Path("workspace/reports/security_props.json")) and props.is_file()
    line = next(int(k) for k, v in meta["line_names"].items() if v == "L4_auth_state_session_login")
    item = {"file": Path(meta["meta_file"]).name, "line": line + 1, "kind": "user assertion", "annotation": "\\false"}
    rwf.name_meta_goal(item, meta)
    assert item["annotation"] == "L4_auth_state_session_login: meta: \\false"
    assert rwf.goal_obligation_class(item) == "l4_auth_state"
    # Off, or a function without properties: no meta file.
    assert rwf.resolve_security_meta("none", Path("/target/session.c"), "session_reset", tmp_path / "wp") is None
    assert rwf.resolve_security_meta(None, Path("/target/session.c"), "session_login", tmp_path / "wp") is None
    missing = rwf.resolve_security_meta("nope.json", Path("/target/session.c"), "session_reset", tmp_path / "wp")
    assert missing is not None and missing["error"]


# ---------------------------------------------------------------------------------------------------
# Ledger and briefs
# ---------------------------------------------------------------------------------------------------

SESSION_DAG = {
    "callgraph_source": "frama_c",
    "modules": {"libsession.a": {"tier": "Tier 1A (Untrusted Binary / Network Parser)"}},
    "functions": {
        name: {
            "name": name,
            "file": "session.c",
            "module": "libsession.a",
            "wave": 0,
            "has_loops": name == "session_close",
        }
        for name in ("session_close", "session_reset", "session_copy_state", "session_login")
    },
}


def _seed_session(run_dir: Path) -> dict:
    write_json(run_dir / "workspace/reports/callgraph_dag.json", SESSION_DAG)
    write_json(run_dir / "workspace/reports/security_props.json", session_props())
    return L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "frama_c")


@pytest.mark.unit
def test_ledger_units_keyed_to_the_properties(run_dir):
    out = _seed_session(run_dir)
    assert out["security_props"]["status"] == "ok" and out["security_props"]["functions"] == 3
    units = {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}
    close = units["session.c#session_close::l6_wiped"]
    assert close["status"] == "planned"
    assert close["bookkeeping"]["security_properties"] == ["L6_wiped_session_key"]
    assert units["session.c#session_reset::l4_auth_state"]["bookkeeping"]["security_properties"] == [
        "L4_auth_state_session_login"
    ]
    assert "session.c#session_copy_state::l3_frame" in units
    assert not [c for c in units if c.startswith("session.c#session_login::l")]
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("report", "status"), [("wp_close_unwiped.json", "blocked"), ("wp_close_wiped.json", "covered")]
)
def test_wipe_proof_decides_the_l6_unit(run_dir, report, status):
    _seed_session(run_dir)
    path = run_dir / "workspace/reports/wp" / report
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / report, path)
    L.cmd_ingest_wp([path])
    units = {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}
    assert units["session.c#session_close::l6_wiped"]["status"] == status


SESSION_SINK_DAG: dict = json.loads(json.dumps(SESSION_DAG))
SESSION_SINK_DAG["functions"].update(
    {
        name: {"name": name, "file": "session.c", "module": "libsession.a", "wave": 0, "has_loops": False}
        for name in ("session_admin", "session_status")
    }
)


def _seed_sinks(run_dir: Path, doc: dict | None = None, refresh: bool = False) -> dict[str, dict]:
    write_json(run_dir / "workspace/reports/callgraph_dag.json", SESSION_SINK_DAG)
    write_json(run_dir / "workspace/reports/security_props.json", doc or session_props())
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "frama_c", refresh=refresh)
    return {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}


@pytest.mark.unit
def test_a_literal_decided_from_the_model_is_recorded_by_the_seed(run_dir):
    """Plan step M2: session_admin hands the log sink a literal only; the seed covers its L5 unit."""
    units = _seed_sinks(run_dir)
    admin = units["session.c#session_admin::l5_sanitized"]
    assert admin["status"] == "covered" and not admin["unresolved"]
    assert [(e["phase"], e["result"], e["discharging"]) for e in admin["evidence"]] == [
        ("static", "decided_syntactically", True)
    ]
    assert admin["evidence"][0]["tool_output"] == "workspace/reports/security_props.json"
    assert admin["bookkeeping"]["decided_properties"][0]["property"] == "L5_sanitized_log_line"
    assert "security_properties" not in admin["bookkeeping"]
    # session_status passes a non-literal: its unit waits for WP.
    status = units["session.c#session_status::l5_sanitized"]
    assert status["status"] == "planned" and status["bookkeeping"]["security_properties"] == ["L5_sanitized_log_line"]
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.unit
def test_a_literal_with_a_line_break_blocks_the_unit_and_wp_cannot_credit_it(run_dir):
    m = session_model()
    m["functions"]["session.c#session_admin"]["call_sites"][0]["literals"]["0"] = "admin\r\ncommand"
    doc = sp.generate(m, trust.load_threat_model(FIX / "secret_unwiped" / "THREAT_MODEL.md"))
    assert not sp.validate(doc)
    decided = by_name(doc)["L5_sanitized_log_line"]["decided"]
    assert decided[0]["verdict"] == "violated" and '"admin\\r\\ncommand"' in decided[0]["reason"]
    units = _seed_sinks(run_dir, doc)
    admin = units["session.c#session_admin::l5_sanitized"]
    assert admin["status"] == "blocked" and admin["evidence"][0]["result"] == "decided_violated"
    assert admin["unresolved"][0].startswith("L5_sanitized_log_line violated (decided from the model)")
    # The literal is fixed, then broken again: a refresh decides again, the seed's decision is not evidence.
    units = _seed_sinks(run_dir, session_props(), refresh=True)
    assert units["session.c#session_admin::l5_sanitized"]["status"] == "covered"
    units = _seed_sinks(run_dir, doc, refresh=True)
    assert units["session.c#session_admin::l5_sanitized"]["status"] == "blocked"
    assert not L.validate_ledger(list(units.values()))
    # No WP result credits a unit decided violated.
    report = json.loads((FIX / "wp_close_wiped.json").read_text(encoding="utf-8"))
    report.update(function="session_admin", by_obligation_class={"l5_sanitized": {"proven": 1, "unproven": 0}})
    path = _write(run_dir / "workspace/reports/wp/admin.json", report)
    L.cmd_ingest_wp([path])
    after = {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}
    assert after["session.c#session_admin::l5_sanitized"]["status"] == "blocked"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("loaded", "error", "status"),
    [
        (["L6_no_leak_session_key"], None, "covered"),
        ([], None, "planned"),
        (["L6_no_leak_session_key"], "x", "planned"),
    ],
)
def test_an_instance_metacsl_decides_statically_is_credited(run_dir, loaded, error, status):
    """
    The M1 bug: MetAcsl's -meta-simpl drops an instance it decides statically, so the WP run of an
    instance function that loaded the property ends all_proven with no goal of the class. Credited when
    the report says the property was loaded without error.
    """
    _seed_sinks(run_dir)
    report = json.loads((FIX / "wp_close_wiped.json").read_text(encoding="utf-8"))
    sp_block = {"props": "workspace/reports/security_props.json", "properties": loaded}
    if error:
        sp_block["error"] = error
    report.update(
        function="session_admin",
        by_obligation_class={"rte": {"proven": 1, "proven_under_hyp": 0, "unproven": 0}},
        layer_goals=[],
        security_props=sp_block,
    )
    report["limits"]["unchecked_layer_clauses"] = []
    path = _write(run_dir / "workspace/reports/wp/admin.json", report)
    L.cmd_ingest_wp([path])
    units = {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}
    leak = units["session.c#session_admin::l6_no_leak"]
    assert leak["status"] == status
    if status == "covered":
        assert leak["evidence"][-1]["result"] == "wp_meta_simplified"
    else:
        assert leak["evidence"][-1]["result"] == "wp_no_credited_goals"
    # The unit decided from the model is left alone by WP.
    admin = units["session.c#session_admin::l5_sanitized"]
    assert admin["status"] == "covered" and [e["phase"] for e in admin["evidence"]] == ["static"]
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.unit
def test_text_sink_literals_are_decided_per_caller():
    def site(callee: str, line: int, **lits: str) -> dict:
        return {"callee": callee, "line": line, "literals": {k.lstrip("a"): v for k, v in lits.items()}}

    sites = {
        "a.c#lit": [site("log2", 3, a1="hello")],
        "a.c#crlf": [site("log2", 4, a1="a\nb")],
        "a.c#after_nul": [site("log2", 5, a1="ok\0\n")],
        "a.c#mixed": [site("log2", 6, a1="ok"), site("log2", 7)],
        "a.c#var": [site("log2", 8)],
        "a.c#other": [site("log2", 9, a0="x")],
    }
    funcs = {fid: fn(fid.split("#")[1], external_calls=["log2"], call_sites=s) for fid, s in sites.items()}
    m = model(
        funcs, external_formals={"log2": [{"name": "lvl", "kind": "value"}, {"name": "msg", "kind": "const_pointer"}]}
    )
    t = threat(output_sinks=[{"function": "log2", "kind": "log", "params": ["msg"], "description": "d"}])
    doc = sp.generate(m, t)
    assert not sp.validate(doc), sp.validate(doc)
    prop = by_name(doc)["L5_sanitized_log2"]
    verdicts = {d["function"]: d["verdict"] for d in prop["decided"]}
    assert verdicts == {"a.c#lit": "satisfied", "a.c#crlf": "violated", "a.c#after_nul": "satisfied"}
    assert prop["instances"] == ["a.c#mixed", "a.c#other", "a.c#var"]
    assert any(n.startswith("mixed: call(s) log2 with string literals and with other text") for n in prop["notes"])
    assert doc["obligations"]["a.c#crlf"][0]["decided"] == "violated"
    # A model without call sites decides nothing, and says why.
    for f in m["functions"].values():
        del f["call_sites"]
    old = sp.generate(m, t)
    assert (
        "decided" not in by_name(old)["L5_sanitized_log2"] and len(by_name(old)["L5_sanitized_log2"]["instances"]) == 6
    )
    assert any("no call sites with their string-literal arguments" in w for w in old["warnings"])


@pytest.mark.unit
def test_model_call_sites_from_the_dump():
    import phase0_model as pm

    dump_fn = {
        "calls": [
            {"name": "log_line", "indirect": False, "literal_args": {"0": "hi"}, "loc": "/t/a.c:4:2-9"},
            {"indirect": True, "expr": "fp", "loc": "/t/a.c:5"},
            {"name": "g", "indirect": False, "literal_args": {}, "loc": "/t/a.c:6"},
        ]
    }
    assert pm._body_facts(dump_fn)["call_sites"] == [
        {"callee": "log_line", "line": 4, "literals": {"0": "hi"}},
        {"callee": "g", "line": 6, "literals": {}},
    ]
    # A dump before schema 4 has no literal_args: no call sites, so "no literal" is never assumed.
    assert "call_sites" not in pm._body_facts({"calls": [{"name": "g", "indirect": False, "loc": "/t/a.c:6"}]})
    assert "call_sites" not in pm._body_facts(dump_fn, literals=False)


@pytest.mark.unit
def test_brief_entries_name_what_to_discharge():
    doc = session_props()
    entries = sp.brief_entries(doc, "session.c", "session_copy_state")
    assert [e["obligation_class"] for e in entries] == ["l3_frame", "l4_auth_state"]
    assert (
        entries[1]["metacsl"].startswith("/*@ meta \\prop") and "L4_auth_state_session_login" in entries[1]["discharge"]
    )
    assert sp.brief_entries(doc, "session.c", "session_login") == []


@pytest.mark.unit
def test_dag_no_longer_infers_layers_4_to_6():
    from build_callgraph_dag import termination_properties

    rec = {
        "has_loops": False,
        "loop_count": 0,
        "writes_bounded_buffer": True,
        "uses_format_or_write": True,
        "has_zeroization": True,
    }
    assert termination_properties(rec) == []


# ---------------------------------------------------------------------------------------------------
# Acceptance (Docker): unwiped -> unproven L6 unit, wiped -> proven
# ---------------------------------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(("variant", "proven"), [("secret_unwiped", False), ("secret_wiped", True)])
def test_wipe_acceptance_in_the_image(model_run, tmp_path, variant, proven):  # noqa: F811
    fixture = FIX / variant
    run = tmp_path / "run"
    m = model_run(fixture, run, "make")
    assert m["status"] == "ok" and m["functions"]["session.c#session_close"]["writes"]["globals"]
    doc = sp.generate(m, trust.load_threat_model(fixture / "THREAT_MODEL.md"))
    assert not sp.validate(doc)
    write_json(run / "workspace/reports/security_props.json", doc)
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{fixture.resolve()}:/target:ro", "-v", f"{run.resolve()}:/framac-run", "-w", "/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        ANALYSIS_IMAGE, "-c",
        "python3 /opt/framac-pipeline/scripts/run_wp_function.py --file /target/session.c --function session_close "
        "--out-dir workspace/wp --cppflags=-I/target --timeout 10 --out-json workspace/reports/wp/session_close.json",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    report = json.loads((run / "workspace/reports/wp/session_close.json").read_text(encoding="utf-8"))
    assert report["security_props"]["properties"] == ["L6_wiped_session_key"]
    counts = report["by_obligation_class"]["l6_wiped"]
    assert (counts["proven"], counts["unproven"]) == ((1, 0) if proven else (0, 1))
    assert (report["status"] == "all_proven") is proven


# ---------------------------------------------------------------------------------------------------
# Acceptance (Docker): every MetAcsl template variant, against the real MetAcsl (plan step M1)
# ---------------------------------------------------------------------------------------------------

VARIANTS_DIR = FIX / "variants"
LOG_SINK = {"function": "log_line", "kind": "log", "params": ["msg"], "description": "Log lines."}
LOGIN_GATE = {"function": "login", "state": "auth_ok", "protects": ["admin"], "description": "d"}
CHECK_GATE = {"function": "check", "state": "s->ok", "protects": ["act"], "description": "d"}

# variant -> (function under WP, property name, threat-model lists). Each variants/<variant>.c
# satisfies the property; built with -DVIOLATE it violates it in the function under WP.
TEMPLATE_VARIANTS: dict[str, tuple[str, str, dict]] = {
    "l4_auth_required_global": ("dispatch", "L4_auth_required_login", {"auth_gates": [LOGIN_GATE]}),
    "l4_auth_required_formal": ("serve", "L4_auth_required_check", {"auth_gates": [CHECK_GATE]}),
    "l4_auth_state_global": ("store", "L4_auth_state_login", {"auth_gates": [LOGIN_GATE]}),
    "l4_auth_state_formal": ("bump", "L4_auth_state_check", {"auth_gates": [CHECK_GATE]}),
    "l5_sanitized_text": ("report", "L5_sanitized_log_line", {"output_sinks": [LOG_SINK]}),
    "l5_sanitized_bytes": (
        "emit",
        "L5_sanitized_send_bytes",
        {"output_sinks": [{"function": "send_bytes", "kind": "network", "length": "n", "description": "d"}]},
    ),
    "l5_sanitized_object": (
        "emit",
        "L5_sanitized_send_msg",
        {"output_sinks": [{"function": "send_msg", "kind": "ipc", "description": "d"}]},
    ),
    # A sink the target defines and calls through a function pointer: the property is its precondition.
    "l5_sanitized_entry_text": ("report", "L5_sanitized_log_line", {"output_sinks": [LOG_SINK]}),
    "l5_sanitized_entry_object": (
        "emit",
        "L5_sanitized_send_msg",
        {"output_sinks": [{"function": "send_msg", "kind": "ipc", "description": "d"}]},
    ),
    "l5_sanitized_buffer": (
        "finish",
        "L5_sanitized_finish",
        {"output_sinks": [{"function": "finish", "kind": "buffer", "description": "d"}]},
    ),
    "l6_no_leak_calling": (
        "show",
        "L6_no_leak_key",
        {"secrets": [{"name": "key", "kind": "global", "description": "d"}], "output_sinks": [LOG_SINK]},
    ),
    "l6_no_leak_calling_static": (
        "show",
        "L6_no_leak_key",
        {"secrets": [{"name": "key", "kind": "global", "description": "d"}], "output_sinks": [LOG_SINK]},
    ),
    "l6_no_leak_reading": (
        "log_line",
        "L6_no_leak_key",
        {"secrets": [{"name": "key", "kind": "global", "description": "d"}], "output_sinks": [LOG_SINK]},
    ),
    "l6_no_leak_parameter": (
        "derive",
        "L6_no_leak_key",
        {
            "secrets": [{"name": "key", "kind": "parameter", "function": "derive", "size": "len", "description": "d"}],
            "output_sinks": [{"function": "net_send", "kind": "network", "length": "n", "description": "d"}],
        },
    ),
    "l6_wiped_scalar": (
        "drop",
        "L6_wiped_token",
        {"secrets": [{"name": "token", "kind": "global", "function": "drop", "description": "d"}]},
    ),
    "l6_wiped_parameter": (
        "burn",
        "L6_wiped_key",
        {"secrets": [{"name": "key", "kind": "parameter", "function": "burn", "size": "len", "description": "d"}]},
    ),
    "l6_wiped_field": (
        "ctx_free",
        "L6_wiped_secret",
        {"secrets": [{"name": "secret", "kind": "field", "object": "ctx", "function": "ctx_free", "description": "d"}]},
    ),
}
# A goal named apart from its property: the `reading` half of a global secret's no-leak property.
GOAL_NAMES = {"l6_no_leak_reading": "L6_no_leak_read_key"}
# Variants whose satisfied program MetAcsl decides statically (-meta-simpl drops the instance): no
# goal is left, and the ledger credits the unit from the report's loaded properties.
STATIC_VARIANTS = {"l6_no_leak_calling_static"}
# Open pipeline bugs (docs/troubleshooting/security-properties.md): (variant, violate) -> reason.
OPEN_DEFECTS: dict[tuple[str, bool], str] = {}


def _variant_params() -> list:
    out = []
    for variant in sorted(TEMPLATE_VARIANTS):
        for violate in (False, True):
            reason = OPEN_DEFECTS.get((variant, violate))
            marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
            out.append(
                pytest.param(variant, violate, marks=marks, id=f"{variant}-{'violated' if violate else 'satisfied'}")
            )
    return out


_VARIANT_MAKEFILE = """CC ?= cc
CFLAGS = -O0 -g -Wall -Wextra -std=c99 {defs}

all: libprog.a

prog.o: prog.c
\t$(CC) $(CFLAGS) -c -o $@ prog.c

libprog.a: prog.o
\tar rcs $@ prog.o
"""


def _one_file_target(dest: Path, source: Path, lists: dict, violate: bool) -> Path:
    """A one-file target: `source` as prog.c, its Makefile and a THREAT_MODEL.md with `lists`."""
    dest.mkdir(parents=True)
    shutil.copy(source, dest / "prog.c")
    defs = "-DVIOLATE" if violate else ""
    (dest / "Makefile").write_text(_VARIANT_MAKEFILE.format(defs=defs), encoding="utf-8", newline="\n")
    block: dict = {"schema_version": 1, "target": source.stem, "input_sources": [], "trusted_callers": []}
    block.update({"secrets": [], "auth_gates": [], "output_sinks": []})
    block.update(lists)
    text = f"# Threat model: {source.stem}\n\n```json framac-threat-model\n{json.dumps(block, indent=1)}\n```\n"
    (dest / "THREAT_MODEL.md").write_text(text, encoding="utf-8", newline="\n")
    return dest


def _variant_target(dest: Path, variant: str, violate: bool) -> Path:
    """variants/<variant>.c as a one-file target with its threat model."""
    return _one_file_target(dest, VARIANTS_DIR / f"{variant}.c", TEMPLATE_VARIANTS[variant][2], violate)


def _seed_one_file(run: Path, model: dict, doc: dict) -> None:
    """Seed the ledger of a one-file run (cwd `run`) from its model and security properties."""
    dag = {
        "callgraph_source": "frama_c",
        "modules": {"libprog.a": {"tier": "Tier 1A (Untrusted Binary / Network Parser)"}},
        "functions": {
            f["name"]: {"name": f["name"], "file": f["file"], "module": "libprog.a", "wave": 0, "has_loops": False}
            for f in model["functions"].values()
        },
    }
    write_json(run / "workspace/reports/security_props.json", doc)
    write_json(run / "workspace/reports/callgraph_dag.json", dag)
    L.cmd_seed(run / "workspace/reports/callgraph_dag.json", [], "frama_c")


def _ledger_units(run: Path) -> dict[str, dict]:
    return {u["coverage_id"]: u for u in json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))}


@pytest.mark.unit
def test_every_template_variant_has_a_program_and_its_property(tmp_path):
    # The programs of the asset, invariant and call-rule kinds are in KIND_VARIANTS (further down).
    assert sorted(p.stem for p in VARIANTS_DIR.glob("*.c")) == sorted({*TEMPLATE_VARIANTS, *KIND_VARIANTS})
    for variant, (_, name, _) in TEMPLATE_VARIANTS.items():
        threat_model = trust.load_threat_model(_variant_target(tmp_path / variant, variant, False) / "THREAT_MODEL.md")
        assert threat_model["status"] == "ok", (variant, threat_model)
        assert any(name.startswith(prefix) for prefix in sp.NAME_PREFIX.values()), name


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(("variant", "violate"), _variant_params())
def test_template_variant_acceptance_in_the_image(model_run, tmp_path, monkeypatch, variant, violate):  # noqa: F811
    """
    The named goal of each template variant proves on a program that satisfies the property and stays
    unproven on one that violates it: MetAcsl accepts the template and it is not trivially true. A
    satisfied instance MetAcsl decides statically leaves no goal; the ledger credits it all the same.
    """
    function, name, _ = TEMPLATE_VARIANTS[variant]
    target = _variant_target(tmp_path / "target", variant, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert not sp.validate(doc)
    props = by_name(doc)
    assert name in props, doc["warnings"]
    assert f"prog.c#{function}" in props[name]["instances"], props[name]
    write_json(run / "workspace/reports/security_props.json", doc)
    defs = " -DVIOLATE" if violate else ""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{target.resolve()}:/target:ro", "-v", f"{run.resolve()}:/framac-run", "-w", "/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        ANALYSIS_IMAGE, "-c",
        f"python3 /opt/framac-pipeline/scripts/run_wp_function.py --file /target/prog.c --function {function} "
        f"--out-dir workspace/wp '--cppflags=-I/target{defs}' --timeout 10 --out-json workspace/reports/wp/out.json",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    report = json.loads((run / "workspace/reports/wp/out.json").read_text(encoding="utf-8"))
    assert name in report["security_props"]["properties"]
    mine = f"{GOAL_NAMES.get(variant, name)}:"
    proven = [g for g in report["layer_goals"] if str(g.get("annotation") or "").startswith(mine)]
    unproven = [g for g in report["unproven_goals"] if str(g.get("annotation") or "").startswith(mine)]
    detail = json.dumps({"proven": proven, "unproven": unproven, "log": report.get("wp_log_tail")}, indent=1)
    if violate:
        assert unproven, detail
    elif variant in STATIC_VARIANTS:
        assert not proven and not unproven and report["status"] == "all_proven", detail
        monkeypatch.chdir(run)
        _seed_one_file(run, m, doc)
        L.cmd_ingest_wp([run / "workspace/reports/wp/out.json"])
        unit = _ledger_units(run)[f"prog.c#{function}::{props[name]['obligation_class']}"]
        assert unit["status"] == "covered" and unit["evidence"][-1]["result"] == "wp_meta_simplified", unit
    else:
        assert proven and not unproven, detail


# ---------------------------------------------------------------------------------------------------
# Acceptance (Docker): string-literal arguments decided from the real model (plan step M2)
# ---------------------------------------------------------------------------------------------------

DECIDED_DIR = FIX / "decided"
LOG_AT_SINK = {"function": "log_at", "kind": "log", "params": ["msg"], "description": "Leveled log lines."}


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["satisfied", "violated"])
def test_text_literals_are_decided_from_the_real_model(model_run, tmp_path, monkeypatch, violate):  # noqa: F811
    """
    The dump records the literals each call passes (dump schema 4); security_props.py decides the
    callers that hand a text sink literals only, with no goal, and the seed records the verdict.
    """
    lists = {"output_sinks": [LOG_SINK, LOG_AT_SINK]}
    target = _one_file_target(tmp_path / "target", DECIDED_DIR / "l5_text_literal.c", lists, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    sites = m["functions"]["prog.c#report"]["call_sites"]
    expected = (
        [("log_line", {"0": "state:"}), ("log_at", {}), ("log_line", {"0": "injected\nline"})]
        if violate
        else [("log_line", {"0": "state:"}), ("log_at", {"1": "up\0\n"})]
    )
    assert [(s["callee"], s["literals"]) for s in sites] == expected, sites
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert not sp.validate(doc)
    props = by_name(doc)
    line, at = props["L5_sanitized_log_line"], props["L5_sanitized_log_at"]
    assert [d["verdict"] for d in line["decided"]] == ["violated" if violate else "satisfied"]
    assert line["instances"] == []
    if violate:
        # A non-literal argument (a conditional) keeps its goal.
        assert at["instances"] == ["prog.c#report"] and "decided" not in at
    else:
        # No goal is left in `report`: no meta file for its WP run.
        assert at["instances"] == [] and [d["verdict"] for d in at["decided"]] == ["satisfied"]
        assert sp.meta_file_text(doc, "prog.c#report") is None
    monkeypatch.chdir(run)
    _seed_one_file(run, m, doc)
    unit = _ledger_units(run)["prog.c#report::l5_sanitized"]
    assert unit["status"] == ("blocked" if violate else "covered"), unit


# ---------------------------------------------------------------------------------------------------
# Eva taint annotations for indirect secret flows (plan step M3)
# ---------------------------------------------------------------------------------------------------

TAINT_DIR = FIX / "taint"
SESSION_KEY_TSET = "session_key[0 .. sizeof(session_key) / sizeof(session_key[0]) - 1]"


@pytest.mark.unit
def test_taint_plan_names_sources_and_sink_calls():
    plan = by_name(session_props())["L6_no_leak_session_key"]["taint"]
    assert plan["sources"] == [{"function": "session.c#session_set_key", "at": "return", "lvalues": SESSION_KEY_TSET}]
    assert [(c["function"], c["sink"], c["args"]) for c in plan["checks"]] == [
        ("session.c#session_admin", "log_line", [[0, None]]),
        ("session.c#session_status", "log_line", [[0, None]]),
    ]


@pytest.mark.unit
def test_apply_taint_inserts_on_the_same_lines_and_is_idempotent(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    original = (FIX / "secret_unwiped" / "session.c").read_text(encoding="utf-8")
    (work / "session.c").write_text(original, encoding="utf-8", newline="\n")
    doc = session_props()
    out = sp.apply_taint(doc, work)
    text = (work / "session.c").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert len(lines) == len(original.splitlines())
    assert out["files"] == ["session.c"] and out["changed"] == ["session.c"] and not out["skipped"]
    assert out["functions"] == ["session.c#session_admin", "session.c#session_set_key", "session.c#session_status"]
    # No return in session_set_key: the taint goes before its closing brace.
    assert lines[19] == f"/*@ taint {SESSION_KEY_TSET}; */ }}"
    check = "/*@ assert L6_no_leak_session_key: eva_taint: !\\tainted(*((unsigned char const *)({}))); */ "
    assert lines[24] == "    " + check.format('"admin command"') + 'log_line("admin command");'
    assert lines[35].startswith("    " + check.format('session_open ? "open" : "closed"'))
    assert [(c["line"], c["function"]) for c in out["checks"]] == [
        (25, "session.c#session_admin"),
        (36, "session.c#session_status"),
    ]
    # Every annotation is a well-formed comment the tokenizer reads as ACSL.
    assert sum(1 for t in tokenize_c_acsl(text, "session.c") if t.kind == "acsl_block") == 3
    again = sp.apply_taint(doc, work)
    assert again["changed"] == [] and (work / "session.c").read_text(encoding="utf-8") == text
    off = sp.apply_taint({"properties": []}, work)
    assert off["changed"] == ["session.c"] and (work / "session.c").read_text(encoding="utf-8") == original


@pytest.mark.unit
def test_apply_taint_skips_calls_an_assertion_cannot_precede(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    source = (
        "int send(const char *p, int n);\n"
        "char *next(char *p);\n"
        "int f(char *p, int n)\n"
        "{\n"
        "    if (send(p, n) < 0) return -1;\n"
        "    send(next(p), n);\n"
        "    return n > 0 ? send(p, n) : 0;\n"
        "}\n"
        "int g(char *p, int n) { int r = send(p, n); for (;;) send(p + 1, n - 1); return r; }\n"
    )
    (work / "x.c").write_text(source, encoding="utf-8", newline="\n")
    checks = [{"function": f"x.c#{f}", "sink": "send", "args": [[0, 1]]} for f in ("f", "g")]
    props = {"properties": [{"name": "L6_no_leak_k", "taint": {"sources": [], "checks": checks, "notes": []}}]}
    out = sp.apply_taint(props, work)
    assert [s.split(": ", 1)[1] for s in out["skipped"]] == [
        "send call: not a statement of its own",
        "send call: an argument the assertion cannot repeat",
        "send call: not a statement of its own",
    ]
    lines = (work / "x.c").read_text(encoding="utf-8").splitlines()
    region = "((unsigned char const *)({}))[0 .. ({}) - 1]"
    first = "/*@ assert L6_no_leak_k: eva_taint: !\\tainted(" + region.format("p", "n") + "); */ "
    loop = "/*@ assert L6_no_leak_k: eva_taint: !\\tainted(" + region.format("p + 1", "n - 1") + "); */ "
    assert (
        lines[8]
        == f"int g(char *p, int n) {{ {first}int r = send(p, n); for (;;) {loop}send(p + 1, n - 1); return r; }}"
    )
    assert [c["line"] for c in out["checks"]] == [9, 9]


def _taint_report(rows: list[dict], analysed: list[str]) -> dict:
    return {
        "status": "ok",
        "module": "libsession.a",
        "unknown_obligations_by_function": {r["function"]: [r] for r in rows},
        "invalid_alarms": [],
        "dead_alarms": [],
        "functions_with_properties": analysed,
    }


@pytest.mark.unit
def test_eva_taint_statuses_land_on_the_l6_unit(run_dir):
    """A taint Unknown blocks the l6_no_leak unit (not the rte one) and WP cannot credit it; a later clean run reopens it."""
    doc = session_props()
    work = run_dir / "workspace/work"
    work.mkdir(parents=True)
    shutil.copy(FIX / "secret_unwiped" / "session.c", work / "session.c")
    applied = sp.apply_taint(doc, work)
    doc["eva_taint"] = {"enabled": True, **{k: applied[k] for k in ("files", "functions", "checks", "skipped")}}
    assert not sp.validate(doc)
    _seed_sinks(run_dir, doc)
    row = {
        "directory": ".",
        "file": "session.c",
        "function": "session_status",
        "line": 36,
        "kind": "user assertion",
        "status": "Unknown",
        "status_bucket": "Unknown",
        "annotation": '¬\\tainted(*((unsigned char const *)(session_open != 0? "open": "closed")))',
    }
    eva = run_dir / "workspace/reports/eva/libsession.a.json"
    write_json(eva, _taint_report([row], ["session_admin", "session_status"]))
    L.cmd_ingest_eva([eva])
    units = _ledger_units(run_dir)
    status = units["session.c#session_status::l6_no_leak"]
    assert status["status"] == "blocked"
    assert status["unresolved"][0].startswith("Eva taint: L6_no_leak_session_key at line 36")
    assert status["bookkeeping"]["eva_taint"] == {"libsession.a": "unknown"}
    assert units["session.c#session_admin::l6_no_leak"]["evidence"][-1]["result"] == "eva_taint_valid"
    # The taint row is not an RTE obligation of session_status.
    assert units["session.c#session_status::rte"]["bookkeeping"]["eva_verdicts"] == {"libsession.a": "valid"}
    assert L._taint_open(status) == ["libsession.a"]
    # A clean run of the same module: the unit is WP's again.
    write_json(eva, _taint_report([], ["session_admin", "session_status"]))
    L.cmd_ingest_eva([eva])
    status = _ledger_units(run_dir)["session.c#session_status::l6_no_leak"]
    assert status["status"] == "planned" and not status["unresolved"]
    assert status["bookkeeping"]["eva_taint"] == {"libsession.a": "valid"}
    assert not L.validate_ledger(list(_ledger_units(run_dir).values()))


@pytest.mark.unit
def test_wp_cannot_credit_a_unit_with_an_open_taint_check(run_dir):
    _seed_session(run_dir)
    ledger = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    for u in ledger:
        if u["coverage_id"] == "session.c#session_close::l6_wiped":
            u.setdefault("bookkeeping", {})["eva_taint"] = {"libsession.a": "unknown"}
    write_json(run_dir / "coverage-ledger.json", ledger)
    path = run_dir / "workspace/reports/wp/wp_close_wiped.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / "wp_close_wiped.json", path)
    L.cmd_ingest_wp([path])
    unit = _ledger_units(run_dir)["session.c#session_close::l6_wiped"]
    assert unit["status"] != "covered" and not unit["evidence"][-1]["discharging"]
    assert "Eva taint check is open" in unit["evidence"][-1]["summary"]


@pytest.mark.unit
def test_run_turns_taint_on_and_off(run_dir):
    model_path = run_dir / "workspace/reports/phase0_model.json"
    m = session_model()
    m["threat_model"] = {"status": "ok"}
    write_json(model_path, m)
    work = run_dir / "workspace/work"
    work.mkdir(parents=True)
    original = (FIX / "secret_unwiped" / "session.c").read_text(encoding="utf-8")
    (work / "session.c").write_text(original, encoding="utf-8", newline="\n")
    tm = FIX / "secret_unwiped" / "THREAT_MODEL.md"
    real = trust.recorded_threat_model
    try:
        trust.recorded_threat_model = lambda _m: (trust.load_threat_model(tm), None)  # type: ignore[assignment]
        assert sp.main(["run", "--eva-taint"]) == 0
        doc = json.loads((run_dir / "workspace/reports/security_props.json").read_text(encoding="utf-8"))
        assert doc["eva_taint"]["enabled"] and doc["eva_taint"]["files"] == ["session.c"]
        assert "pending" in doc["eva_taint"]  # no harness module yet
        assert "eva_taint" in (work / "session.c").read_text(encoding="utf-8")
        # Sticky: a plain run (the Makefile's) keeps the annotations.
        assert sp.main(["run"]) == 0
        assert "eva_taint" in (work / "session.c").read_text(encoding="utf-8")
        assert sp.main(["run", "--no-eva-taint"]) == 0
        assert (work / "session.c").read_text(encoding="utf-8") == original
        doc = json.loads((run_dir / "workspace/reports/security_props.json").read_text(encoding="utf-8"))
        assert doc["eva_taint"]["enabled"] is False and not sp.validate(doc)
    finally:
        trust.recorded_threat_model = real  # type: ignore[assignment]


@pytest.mark.unit
def test_run_keeps_the_chosen_meta_engines(run_dir):
    """`--meta-engines` is sticky like `--eva-taint`: WP only until asked, and `none` turns it off."""
    model_path = run_dir / "workspace/reports/phase0_model.json"
    m = session_model()
    m["threat_model"] = {"status": "ok"}
    write_json(model_path, m)
    (run_dir / "workspace/work").mkdir(parents=True)
    out = run_dir / "workspace/reports/security_props.json"
    tm = FIX / "secret_unwiped" / "THREAT_MODEL.md"
    real = trust.recorded_threat_model

    def engines() -> list[str]:
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert not sp.validate(doc)
        assert sp.meta_engines(doc) == frozenset(doc["meta_engines"])
        return doc["meta_engines"]

    try:
        trust.recorded_threat_model = lambda _m: (trust.load_threat_model(tm), None)  # type: ignore[assignment]
        assert sp.main(["run"]) == 0 and engines() == []
        assert sp.main(["run", "--meta-engines", "eva"]) == 0 and engines() == ["eva"]
        assert sp.main(["run"]) == 0 and engines() == ["eva"]
        assert sp.main(["run", "--meta-engines", "eacsl,eva"]) == 0 and engines() == ["eacsl", "eva"]
        assert sp.main(["run", "--meta-engines", "none"]) == 0 and engines() == []
        with pytest.raises(SystemExit):
            sp.main(["run", "--meta-engines", "wp"])
    finally:
        trust.recorded_threat_model = real  # type: ignore[assignment]
    assert sp.meta_engines(None) == frozenset() and sp.meta_engines({"meta_engines": ["eva", "x"]}) == {"eva"}


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["no_copy", "copy"])
def test_taint_annotations_in_the_image(model_run, tmp_path, violate):  # noqa: F811
    """
    The generated annotations parse and Eva's taint domain decides them: the copy of the key handed
    to the sink leaves the check Unknown, a buffer that never held it proves it.
    """
    lists = {"secrets": [{"name": "key", "kind": "global", "description": "d"}], "output_sinks": [LOG_SINK]}
    target = _one_file_target(tmp_path / "target", TAINT_DIR / "l6_indirect.c", lists, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    plan = by_name(doc)["L6_no_leak_key"]["taint"]
    assert {s["function"] for s in plan["sources"]} >= {"prog.c#set_key"}
    work = run / "taint-work"
    work.mkdir()
    shutil.copy(target / "prog.c", work / "prog.c")
    applied = sp.apply_taint(doc, work)
    assert not applied["skipped"] and [c["function"] for c in applied["checks"]] == ["prog.c#show"]
    defs = " -cpp-extra-args=-DVIOLATE" if violate else ""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{work.resolve()}:/w", "-w", "/w", ANALYSIS_IMAGE, "-c",
        f"frama-c prog.c{defs} -eva -main eva_main -eva-domains cvalue,taint -then -report-csv out.csv",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    rows = [r.split("\t") for r in (work / "out.csv").read_text(encoding="utf-8").splitlines()]
    taint = [(int(r[2]), r[5]) for r in rows if len(r) > 6 and "\\tainted(" in r[6]]
    assert taint == [(applied["checks"][0]["line"], "Unknown" if violate else "Valid")], res.stdout


# ---------------------------------------------------------------------------------------------------
# Secrets held in a local (plan step M6)
# ---------------------------------------------------------------------------------------------------

LOCAL_DIR = FIX / "local"
LOCAL_SECRET = {"name": "buf", "kind": "local", "function": "derive", "description": "Derived key."}
LOCAL_CHECK = "/*@ check L6_wiped_buf: \\forall integer i; 0 <= i < sizeof(buf) / sizeof(buf[0]) ==> buf[i] == 0; */ "


def _local_doc(**secret) -> dict:
    m = model({"prog.c#derive": fn("derive", "prog.c", formals=[{"name": "n", "kind": "value"}])})
    return sp.generate(m, threat(secrets=[{**LOCAL_SECRET, **secret}], output_sinks=[LOG_SINK]))


@pytest.mark.unit
def test_a_local_secret_is_an_in_code_check():
    doc = _local_doc()
    assert not sp.validate(doc)
    prop = by_name(doc)["L6_wiped_buf"]
    assert prop["instances"] == ["prog.c#derive"] and prop["obligation_class"] == "l6_wiped"
    assert prop["code"] == {"local": "buf", "check": LOCAL_CHECK.rstrip()}
    # Not MetAcsl: no meta file, and the brief says the check is already in the code.
    assert sp.meta_file_text(doc, "prog.c#derive") is None
    assert "already in the code" in sp.brief_entries(doc, "prog.c", "derive")[-1]["discharge"]
    assert any(w.startswith("secret buf: a local: no no-leak property") for w in doc["warnings"])
    sized = by_name(_local_doc(size="n"))["L6_wiped_buf"]
    assert "0 <= i < (n) ==> buf[i] == 0" in sized["code"]["check"]
    assert run_wp_class(prop["name"]) == "l6_wiped"


def run_wp_class(name: str) -> str:
    return rwf.goal_obligation_class({"kind": "check", "annotation": f"{name}: \\forall integer i; ..."})


@pytest.mark.unit
def test_local_checks_go_before_each_return_in_scope(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    source = (LOCAL_DIR / "l6_wiped_local.c").read_text(encoding="utf-8")
    (work / "prog.c").write_text(source, encoding="utf-8", newline="\n")
    doc = _local_doc()
    out = sp.apply_taint(doc, work, taint=False)
    assert not out["skipped"] and out["files"] == [] and out["checks"] == []
    assert [(c["line"], c["property"]) for c in out["code_checks"]] == [(26, "L6_wiped_buf"), (27, "L6_wiped_buf")]
    lines = (work / "prog.c").read_text(encoding="utf-8").splitlines()
    assert lines[25] == "            " + LOCAL_CHECK + "return -1;"
    assert lines[26] == "    " + LOCAL_CHECK + "}"
    # Out of the local's scope: untouched.
    assert lines[11] == "        return -2;" and lines[27] == "    return n;"
    # The same plan again changes nothing; without the property the source is back.
    assert sp.apply_taint(doc, work, taint=False)["changed"] == []
    sp.apply_taint({"properties": []}, work)
    assert (work / "prog.c").read_text(encoding="utf-8") == source


@pytest.mark.unit
def test_report_lists_threat_model_items_without_a_property():
    import generate_report as gr

    m = model({"prog.c#derive": fn("derive", "prog.c")})
    doc = sp.generate(m, threat(secrets=[{"name": "tok", "kind": "return", "function": "derive", "description": "d"}]))
    lines = gr.security_props_lines(doc)
    assert lines[0] == "### Threat-model items without a property"
    assert any("tok" in line and "returned secret" in line and "no property" in line for line in lines)
    assert gr.security_props_lines({"warnings": ["the model has no call sites"]}) == []


@pytest.mark.unit
def test_eva_rows_of_a_local_check_go_to_the_l6_wiped_unit(run_dir):
    m = model({"prog.c#derive": fn("derive", "prog.c", formals=[{"name": "n", "kind": "value"}])})
    doc = _local_doc()
    doc["code_checks"] = [{"file": "prog.c", "line": 26, "function": "prog.c#derive", "property": "L6_wiped_buf"}]
    _seed_one_file(run_dir, m, doc)
    row = {
        "directory": ".",
        "file": "prog.c",
        "function": "derive",
        "line": 26,
        "kind": "user check",
        "status": "Unknown",
        "annotation": "∀ ℤ i; 0 ≤ i < 16 ⇒ buf[i] ≡ 0",
    }
    eva = run_dir / "workspace/reports/eva/libprog.a.json"
    report = {
        "status": "ok",
        "module": "libprog.a",
        "unknown_obligations_by_function": {"derive": [row]},
        "invalid_alarms": [],
        "dead_alarms": [],
        "functions_with_properties": ["derive"],
    }
    write_json(eva, report)
    L.cmd_ingest_eva([eva])
    units = _ledger_units(run_dir)
    assert units["prog.c#derive::l6_wiped"]["evidence"][-1]["result"] == "eva_check_unknown"
    assert units["prog.c#derive::rte"]["bookkeeping"]["eva_verdicts"] == {"libprog.a": "valid"}


@pytest.mark.unit
def test_wp_summary_helper_reads_every_line_and_refuses_an_empty_run():
    """conftest.wp_proved_goals, which the image tests below (and the fc_* ones) read WP logs through."""
    assert wp_proved_goals("[wp] Proved goals:    4 / 4\n  Qed: 4\n") == [(4, 4)]
    assert wp_proved_goals("[wp] Proved goals: 2/3\n") == [(2, 3)]  # spacing as loose as production's pattern
    # Every summary line: a second run that leaves a goal open is not hidden by the first.
    assert wp_proved_goals("[wp] Proved goals:   5 / 5\n...\n[wp] Proved goals:   1 / 2\n") == [(5, 5), (1, 2)]
    # `0 / 0` has proved == total and proves nothing; a log without a summary proves nothing either.
    for log in (
        "[wp] Proved goals:    0 / 0\n",
        "[wp] Proved goals:  3 / 3\n[wp] Proved goals:  0 / 0\n",
        "[wp] 3 goals\n",
    ):
        with pytest.raises(AssertionError):
            wp_proved_goals(log)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["wiped", "refilled"])
def test_local_wipe_check_in_the_image(model_run, tmp_path, violate):  # noqa: F811
    """The in-code check proves when the local is wiped before the return, and not when it is refilled."""
    lists = {"secrets": [LOCAL_SECRET]}
    target = _one_file_target(tmp_path / "target", LOCAL_DIR / "l6_wiped_local.c", lists, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert by_name(doc)["L6_wiped_buf"]["instances"] == ["prog.c#derive"], doc["warnings"]
    work = run / "local-work"
    work.mkdir()
    shutil.copy(target / "prog.c", work / "prog.c")
    assert len(sp.apply_taint(doc, work, taint=False)["code_checks"]) == 2
    defs = " -cpp-extra-args=-DVIOLATE" if violate else ""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{work.resolve()}:/w", "-w", "/w", ANALYSIS_IMAGE, "-c",
        f"frama-c prog.c{defs} -wp -wp-fct derive -wp-prop L6_wiped_buf -wp-timeout 10 -wp-par 1",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    goals = wp_proved_goals(res.stdout)
    assert all(total >= 2 for _, total in goals), res.stdout
    assert all(proved == total for proved, total in goals) is (not violate), res.stdout


# ---------------------------------------------------------------------------------------------------
# Format strings (plan step M5)
# ---------------------------------------------------------------------------------------------------

SYSLOG_FORMALS = [{"name": "priority", "kind": "value"}, {"name": "format", "kind": "const_pointer"}]
SYSLOG_SINK = {"function": "syslog", "kind": "log", "params": ["format"], "format": "format", "description": "d"}
WRAPPER_SINK = {"function": "log_fmt", "kind": "log", "params": ["fmt"], "format": "fmt", "description": "d"}


def _format_model() -> dict:
    def site(callee: str, line: int, literals: dict) -> dict:
        return {"callee": callee, "line": line, "literals": literals}

    return model(
        {
            "f.c#good": fn("good", "f.c", external_calls=["syslog"], call_sites=[site("syslog", 5, {"1": "id %d"})]),
            "f.c#bad": fn(
                "bad",
                "f.c",
                external_calls=["syslog"],
                call_sites=[site("syslog", 9, {"1": "ok"}), site("syslog", 10, {})],
            ),
            "f.c#log_fmt": fn(
                "log_fmt",
                "f.c",
                external_calls=["syslog"],
                formals=[{"name": "fmt", "kind": "const_pointer"}],
                call_sites=[site("syslog", 14, {})],
            ),
            "f.c#user": fn("user", "f.c", call_sites=[site("log_fmt", 20, {"0": "x=%s"})]),
        },
        edges=[("f.c#user", "f.c#log_fmt")],
        external_formals={"syslog": SYSLOG_FORMALS},
    )


@pytest.mark.unit
def test_a_format_argument_is_decided_from_the_model():
    doc = sp.generate(_format_model(), threat(output_sinks=[SYSLOG_SINK, WRAPPER_SINK]))
    assert not sp.validate(doc)
    props = by_name(doc)
    syslog = props["L5_sanitized_format_syslog"]
    assert syslog["instances"] == [] and syslog["obligation_class"] == "l5_sanitized"
    assert [(d["function"], d["verdict"]) for d in syslog["decided"]] == [
        ("f.c#bad", "violated"),
        ("f.c#good", "satisfied"),
    ]
    assert "line 10; CWE-134" in syslog["decided"][0]["reason"]
    # The wrapper forwards its own format: its caller is checked instead.
    assert any("log_fmt is a format sink itself" in n for n in syslog["notes"])
    assert [(d["function"], d["verdict"]) for d in props["L5_sanitized_format_log_fmt"]["decided"]] == [
        ("f.c#user", "satisfied")
    ]
    # `bad` keeps its no-CRLF goal (a non-literal argument); the format property never has one.
    meta = sp.meta_file_text(doc, "f.c#bad")
    assert meta is not None and meta[1] == ["L5_sanitized_syslog"]


@pytest.mark.unit
def test_a_format_problem_is_a_warning():
    bad = {**SYSLOG_SINK, "format": "fmt"}
    doc = sp.generate(_format_model(), threat(output_sinks=[bad]))
    assert (
        "output sink syslog: format fmt is not one of its parameters: L5 format property not generated"
        in doc["warnings"]
    )
    unnamed = _format_model()
    unnamed["external_formals"]["syslog"] = [
        {"name": "param0", "kind": "value"},
        {"name": "param1", "kind": "const_pointer"},
    ]
    doc = sp.generate(unnamed, threat(output_sinks=[{**SYSLOG_SINK, "params": ["param1"]}]))
    assert any("its prototype names none: write its 0-based position, param0, param1" in w for w in doc["warnings"])
    old = _format_model()
    for f in old["functions"].values():
        f.pop("call_sites")
    doc = sp.generate(old, threat(output_sinks=[SYSLOG_SINK]))
    assert any(w.startswith("output sink syslog: the model has") and "format not decided" in w for w in doc["warnings"])
    assert "L5_sanitized_format_syslog" not in by_name(doc)


@pytest.mark.unit
def test_threat_model_schema_takes_a_sink_format(tmp_path):
    block = {"schema_version": 1, "input_sources": [], "secrets": [], "auth_gates": [], "output_sinks": [SYSLOG_SINK]}
    path = tmp_path / "THREAT_MODEL.md"
    path.write_text(f"# Threat model\n\n```json framac-threat-model\n{json.dumps(block)}\n```\n", encoding="utf-8")
    assert trust.load_threat_model(path)["status"] == "ok"
    # The test wrote CRLF line endings on Windows and LF elsewhere; both are read.
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert trust.load_threat_model(path)["status"] == "ok"
    block["output_sinks"] = [{**SYSLOG_SINK, "format": "not a name"}]
    path.write_text(f"# Threat model\n\n```json framac-threat-model\n{json.dumps(block)}\n```\n", encoding="utf-8")
    assert trust.load_threat_model(path)["status"] == trust.STATUS_INVALID


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["literal", "user_format"])
def test_format_strings_are_decided_from_the_real_model(model_run, tmp_path, monkeypatch, violate):  # noqa: F811
    """The dump records syslog's literal format; a call passing the user's text as format blocks the unit."""
    # Frama-C's libc declares `syslog(int, const char *, ...)`: the kernel names the formals param0, param1...
    sink = {**SYSLOG_SINK, "params": ["param1"], "format": "param1"}
    target = _one_file_target(tmp_path / "target", DECIDED_DIR / "l5_format.c", {"output_sinks": [sink]}, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert not sp.validate(doc)
    prop = by_name(doc).get("L5_sanitized_format_syslog")
    assert prop is not None, doc["warnings"]
    assert [d["verdict"] for d in prop["decided"]] == ["violated" if violate else "satisfied"], prop
    monkeypatch.chdir(run)
    _seed_one_file(run, m, doc)
    unit = _ledger_units(run)["prog.c#report::l5_sanitized"]
    if violate:
        assert unit["status"] == "blocked", unit
    else:
        assert unit["status"] != "blocked" and any(
            d["property"] == "L5_sanitized_format_syslog" for d in unit["bookkeeping"]["decided_properties"]
        ), unit


# ---------------------------------------------------------------------------------------------------
# The gate sets the state only on success (plan step M7)
# ---------------------------------------------------------------------------------------------------

GATE_DIR = FIX / "gate"
SUCCESS_GATE = {**LOGIN_GATE, "success": "0"}
FAILURE_CHECK = "/*@ check L4_auth_state_login_on_failure: ({}) != (0) ==> auth_ok == \\at(auth_ok, Pre); */ "


def _gate_model() -> dict:
    return model(
        {
            "prog.c#login": fn("login", "prog.c", formals=[{"name": "pw", "kind": "value"}]),
            "prog.c#dispatch": fn("dispatch", "prog.c"),
            "prog.c#admin": fn("admin", "prog.c"),
        },
        edges=[("prog.c#dispatch", "prog.c#login"), ("prog.c#dispatch", "prog.c#admin")],
        global_variables={"auth_ok": {"name": "auth_ok", "file": "prog.c", "type": "int"}},
    )


@pytest.mark.unit
def test_a_gate_success_value_is_an_in_code_check():
    doc = sp.generate(_gate_model(), threat(auth_gates=[SUCCESS_GATE]))
    assert not sp.validate(doc), sp.validate(doc)
    prop = by_name(doc)["L4_auth_state_login_on_failure"]
    assert prop["instances"] == ["prog.c#login"] and prop["obligation_class"] == "l4_auth_state"
    assert prop["code"] == {"returns": True, "check": FAILURE_CHECK.format("${result}").rstrip()}
    assert rwf.goal_obligation_class({"kind": "check", "annotation": prop["code"]["check"][4:]}) == "l4_auth_state"
    assert sp.meta_file_text(doc, "prog.c#login") is None
    assert "success path only" in sp.brief_entries(doc, "prog.c", "login")[-1]["discharge"]
    # Without `success` nothing changes.
    assert "L4_auth_state_login_on_failure" not in by_name(sp.generate(_gate_model(), threat(auth_gates=[LOGIN_GATE])))


@pytest.mark.unit
def test_gate_checks_go_before_each_return(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    source = (GATE_DIR / "l4_gate_failure.c").read_text(encoding="utf-8")
    source += "int other(int x)\n{\n    return x;\n}\nint login2(void) { return next(); }\n"
    (work / "prog.c").write_text(source, encoding="utf-8", newline="\n")
    doc = sp.generate(_gate_model(), threat(auth_gates=[SUCCESS_GATE]))
    out = sp.apply_taint(doc, work, taint=False)
    assert not out["skipped"]
    assert [c["line"] for c in out["code_checks"]] == [9, 12, 15]
    lines = (work / "prog.c").read_text(encoding="utf-8").splitlines()
    assert lines[11] == "        " + FAILURE_CHECK.format("-1") + "return -1;"
    assert lines[14] == "    " + FAILURE_CHECK.format("0") + "return 0;"
    assert lines[26] == "    return x;"
    # A returned call cannot be repeated in the check: skipped and said so.
    gate2 = {**SUCCESS_GATE, "function": "login2"}
    m = _gate_model()
    m["functions"]["prog.c#login2"] = fn("login2", "prog.c", formals=[])
    out = sp.apply_taint(sp.generate(m, threat(auth_gates=[gate2])), work, taint=False)
    assert out["skipped"] == ["prog.c:29: login2 return: a returned expression the check cannot repeat"]


@pytest.mark.unit
def test_threat_model_schema_takes_a_gate_success(tmp_path):
    path = tmp_path / "THREAT_MODEL.md"
    for success, status in (("0", "ok"), (1, "ok"), ("AUTH_OK", "ok"), ("x; y", trust.STATUS_INVALID)):
        block = {"schema_version": 1, "input_sources": [], "secrets": [], "output_sinks": []}
        block["auth_gates"] = [{**LOGIN_GATE, "success": success}]
        path.write_text(f"# Threat model\n\n```json framac-threat-model\n{json.dumps(block)}\n```\n", encoding="utf-8")
        assert trust.load_threat_model(path)["status"] == status, success


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["set_on_success", "set_before_check"])
def test_gate_failure_check_in_the_image(model_run, tmp_path, violate):  # noqa: F811
    """A gate that sets the state before its check fails the generated check; one that sets it on success proves it."""
    target = _one_file_target(
        tmp_path / "target", GATE_DIR / "l4_gate_failure.c", {"auth_gates": [SUCCESS_GATE]}, violate
    )
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert by_name(doc)["L4_auth_state_login_on_failure"]["instances"] == ["prog.c#login"], doc["warnings"]
    work = run / "gate-work"
    work.mkdir()
    shutil.copy(target / "prog.c", work / "prog.c")
    # Both #ifdef branches hold returns: three checks in the text, two in either build.
    assert len(sp.apply_taint(doc, work, taint=False)["code_checks"]) == 3
    defs = " -cpp-extra-args=-DVIOLATE" if violate else ""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{work.resolve()}:/w", "-w", "/w", ANALYSIS_IMAGE, "-c",
        f"frama-c prog.c{defs} -wp -wp-fct login -wp-prop L4_auth_state_login_on_failure -wp-timeout 10 -wp-par 1",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    goals = wp_proved_goals(res.stdout)
    assert all(total >= 2 for _, total in goals), res.stdout
    assert all(proved == total for proved, total in goals) is (not violate), res.stdout


# ---------------------------------------------------------------------------------------------------
# L5 placement on forwarding sinks (package A of docs/plans/metacsl-exploitation-plan.md)
# ---------------------------------------------------------------------------------------------------

FORWARD_DIR = FIX / "forward"
_SEND_FORMALS = [
    {"name": "ctx", "kind": "pointer"},
    {"name": "req", "kind": "const_pointer"},
    {"name": "req_length", "kind": "value"},
]
_PRE_FORMALS = [{"name": "req", "kind": "pointer"}, {"name": "req_length", "kind": "value"}]


def _net(function: str, param: str = "req", length: str = "req_length") -> dict:
    return {"function": function, "kind": "network", "params": [param], "length": length, "description": "d"}


FORWARD_WRAPPER = _net("send_msg", "msg", "msg_length")
FORWARD_INNER = _net("tcp_send")


def _graph(functions: dict, direct=(), sites=(), **extra) -> dict:
    """A model with direct edges and indirect call sites, each (caller, called expression, candidates)."""
    m = model(functions, edges=direct, **extra)
    m["indirect_sites"] = []
    for n, (caller, expr, candidates) in enumerate(sites):
        m["indirect_sites"].append(
            {
                "unit": "liba.a",
                "caller": caller,
                "expr": expr,
                "signature": "int(void *)",
                "loc": f"m.c:{60 + n}",
                "candidates": list(candidates),
            }
        )
        m["edges"] += [
            {"caller": caller, "callee": c, "kind": "indirect", "sources": ["type-match"]} for c in candidates
        ]
    return m


def _modbus_model(rtu: bool = False) -> dict:
    """
    libmodbus's shape: write_register calls send_msg, which has the backend complete the request
    (send_msg_pre) and then calls the backend's send, both through the backend's function pointers.
    With `rtu`, a second backend whose send transmits through write.
    """
    functions = {
        "m.c#write_register": fn("write_register", "m.c"),
        "m.c#send_msg": fn(
            "send_msg",
            "m.c",
            formals=[
                {"name": "ctx", "kind": "pointer"},
                {"name": "msg", "kind": "pointer"},
                {"name": "msg_length", "kind": "value"},
            ],
        ),
        "tcp.c#tcp_send_msg_pre": fn("tcp_send_msg_pre", "tcp.c", formals=_PRE_FORMALS),
        "tcp.c#tcp_send": fn("tcp_send", "tcp.c", formals=_SEND_FORMALS, external_calls=["send"]),
    }
    pre, send = ["tcp.c#tcp_send_msg_pre"], ["tcp.c#tcp_send"]
    if rtu:
        functions["rtu.c#rtu_send_msg_pre"] = fn("rtu_send_msg_pre", "rtu.c", formals=_PRE_FORMALS)
        functions["rtu.c#rtu_send"] = fn("rtu_send", "rtu.c", formals=_SEND_FORMALS, external_calls=["write"])
        pre.append("rtu.c#rtu_send_msg_pre")
        send.append("rtu.c#rtu_send")
    return _graph(
        functions,
        direct=[("m.c#write_register", "m.c#send_msg")],
        sites=[
            ("m.c#send_msg", "(ctx->backend)->send_msg_pre", pre),
            ("m.c#send_msg", "(ctx->backend)->send", send),
        ],
        external_formals={
            "write": [
                {"name": "fd", "kind": "value"},
                {"name": "buf", "kind": "const_pointer"},
                {"name": "n", "kind": "value"},
            ]
        },
    )


def _sink_warnings(doc: dict) -> list[str]:
    return [w for w in doc["warnings"] if w.startswith("output sink")]


@pytest.mark.unit
def test_a_forwarding_sink_is_checked_at_the_innermost_sink():
    doc = sp.generate(_modbus_model(), threat(output_sinks=[FORWARD_WRAPPER, FORWARD_INNER]))
    assert not sp.validate(doc), sp.validate(doc)
    assert _sink_warnings(doc) == []
    props = by_name(doc)
    wrapper, inner = props["L5_sanitized_send_msg"], props["L5_sanitized_tcp_send"]
    # The wrapper's property has no instance and no MetAcsl text: nothing is checked at its calls.
    assert wrapper["instances"] == [] and wrapper["forwarded_to"] == ["tcp_send"]
    assert "meta \\prop" not in wrapper["acsl"] and "tcp_send" in wrapper["notes"][0]
    assert "m.c#write_register" not in doc["obligations"]
    assert sp.meta_file_text(doc, "m.c#write_register") is None
    # The bytes are checked where they leave: at the wrapper's call of the transmitting sink. That
    # call goes through a pointer, so the property is the sink's precondition.
    assert inner["instances"] == ["m.c#send_msg"] and "forwarded_to" not in inner
    assert "\\targets({tcp_send}), \\context(\\precond)" in inner["acsl"]
    assert "\\fguard(\\initialized(\\formal(req) + (0 .. \\formal(req_length) - 1)))" in inner["acsl"]
    assert [o["property"] for o in doc["obligations"]["m.c#send_msg"]] == ["L5_sanitized_tcp_send"]
    meta = sp.module_meta_file_text(doc)
    assert meta is not None and meta[1] == ["L5_sanitized_tcp_send"]
    entry = sp.brief_entries(doc, "m.c", "send_msg")[0]
    assert "precondition `L5_sanitized_tcp_send`" in entry["discharge"] and "`calls`" in entry["discharge"]
    # A forwarding sink names at least one sink that checks.
    wrapper["forwarded_to"] = []
    assert sp.validate(doc)


@pytest.mark.unit
def test_an_undeclared_backend_keeps_the_wrapper_property_with_a_warning():
    """One call site that reaches a declared sink and a function that reaches none: nothing is dropped."""
    m = _modbus_model(rtu=True)
    doc = sp.generate(m, threat(output_sinks=[FORWARD_WRAPPER, FORWARD_INNER]))
    assert not sp.validate(doc), sp.validate(doc)
    wrapper = by_name(doc)["L5_sanitized_send_msg"]
    assert wrapper["instances"] == ["m.c#write_register"] and "forwarded_to" not in wrapper
    assert "\\context(\\calling)" in wrapper["acsl"]
    warned = _sink_warnings(doc)
    assert len(warned) == 1, warned
    assert "the call through `(ctx->backend)->send` in send_msg (m.c:61)" in warned[0]
    assert "reaches the declared sink(s) tcp_send and also rtu_send, which reach(es) none" in warned[0]
    # The pre-send hooks reach no sink in either backend: that site is no transmit path.
    assert "Declare rtu_send " in warned[0] and "send_msg_pre" not in warned[0]
    # Declaring the other backend's send makes the wrapper forward to both.
    doc = sp.generate(m, threat(output_sinks=[FORWARD_WRAPPER, FORWARD_INNER, _net("rtu_send")]))
    props = by_name(doc)
    assert props["L5_sanitized_send_msg"]["forwarded_to"] == ["rtu_send", "tcp_send"]
    assert props["L5_sanitized_send_msg"]["instances"] == []
    assert props["L5_sanitized_rtu_send"]["instances"] == ["m.c#send_msg"]
    assert props["L5_sanitized_tcp_send"]["instances"] == ["m.c#send_msg"]
    assert _sink_warnings(doc) == []
    # So does declaring what it transmits through: an external sink, checked at its call (\calling)
    # in the function that transmits.
    doc = sp.generate(m, threat(output_sinks=[FORWARD_WRAPPER, FORWARD_INNER, _net("write", "buf", "n")]))
    props = by_name(doc)
    assert props["L5_sanitized_send_msg"]["forwarded_to"] == ["tcp_send", "write"]
    assert props["L5_sanitized_write"]["instances"] == ["rtu.c#rtu_send"]
    assert "\\called == write ==>" in props["L5_sanitized_write"]["acsl"]
    assert _sink_warnings(doc) == []


@pytest.mark.unit
def test_a_candidate_of_another_pointer_type_does_not_stop_the_forwarding():
    """The model's type match ignores const, so the backend's recv is a candidate of the send site."""
    m = _modbus_model()
    recv_formals = [
        {"name": "ctx", "kind": "pointer"},
        {"name": "rsp", "kind": "pointer"},
        {"name": "rsp_length", "kind": "value"},
    ]
    m["functions"]["tcp.c#tcp_recv"] = fn("tcp_recv", "tcp.c", formals=recv_formals, external_calls=["recv"])
    site = next(s for s in m["indirect_sites"] if s["expr"].endswith("->send"))
    site["candidates"].append("tcp.c#tcp_recv")
    m["edges"].append({"caller": "m.c#send_msg", "callee": "tcp.c#tcp_recv", "kind": "indirect"})
    sinks = threat(output_sinks=[FORWARD_WRAPPER, FORWARD_INNER])
    doc = sp.generate(m, sinks)
    assert by_name(doc)["L5_sanitized_send_msg"]["forwarded_to"] == ["tcp_send"]
    assert _sink_warnings(doc) == []
    # Parameters the model does not know (the GCC fallback): it may transmit, so the property stays.
    del m["functions"]["tcp.c#tcp_recv"]["formals"]
    doc = sp.generate(m, sinks)
    assert "forwarded_to" not in by_name(doc)["L5_sanitized_send_msg"]
    assert "and also tcp_recv, which reach(es) none" in _sink_warnings(doc)[0]


@pytest.mark.unit
def test_a_sink_forwards_only_to_another_declared_sink_that_checks_bytes():
    m = _modbus_model()
    # The wrapper alone: its property stays at its callers, and there is nothing to warn about.
    doc = sp.generate(m, threat(output_sinks=[FORWARD_WRAPPER]))
    alone = by_name(doc)["L5_sanitized_send_msg"]
    assert alone["instances"] == ["m.c#write_register"] and "forwarded_to" not in alone
    assert _sink_warnings(doc) == []
    # Text sinks keep their placement: a wrapper does not sanitize, its callers must.
    text = {"function": "send_msg", "kind": "log", "params": ["msg"], "description": "d"}
    inner_text = {"function": "tcp_send", "kind": "log", "params": ["req"], "description": "d"}
    for sinks in ([text, inner_text], [text, FORWARD_INNER], [FORWARD_WRAPPER, inner_text]):
        prop = by_name(sp.generate(m, threat(output_sinks=sinks)))["L5_sanitized_send_msg"]
        assert prop["instances"] == ["m.c#write_register"] and "forwarded_to" not in prop, sinks
    # A declared sink that gets no property (no pointer parameter known) checks nothing: no forwarding to it.
    doc = sp.generate(
        m, threat(output_sinks=[FORWARD_WRAPPER, {"function": "send", "kind": "network", "description": "d"}])
    )
    assert by_name(doc)["L5_sanitized_send_msg"]["instances"] == ["m.c#write_register"]
    assert any(w.startswith("output sink send: no pointer parameter") for w in doc["warnings"])
    # With its parameters named it does, through the direct call in tcp_send.
    props = by_name(sp.generate(m, threat(output_sinks=[FORWARD_WRAPPER, _net("send", "buf", "n")])))
    assert props["L5_sanitized_send_msg"]["forwarded_to"] == ["send"]
    assert props["L5_sanitized_send"]["instances"] == ["tcp.c#tcp_send"]


@pytest.mark.unit
def test_forwarding_follows_a_chain_and_keeps_one_property_in_a_cycle():
    formals = [{"name": "req", "kind": "const_pointer"}, {"name": "req_length", "kind": "value"}]
    functions = {f"a.c#{n}": fn(n, formals=formals) for n in ("user", "outer", "middle", "inner")}
    sinks = [_net("outer"), _net("middle"), _net("inner")]
    chain = model(
        functions, edges=[("a.c#user", "a.c#outer"), ("a.c#outer", "a.c#middle"), ("a.c#middle", "a.c#inner")]
    )
    props = by_name(sp.generate(chain, threat(output_sinks=sinks)))
    assert props["L5_sanitized_outer"]["forwarded_to"] == ["inner"]
    assert props["L5_sanitized_middle"]["forwarded_to"] == ["inner"]
    assert props["L5_sanitized_outer"]["instances"] == props["L5_sanitized_middle"]["instances"] == []
    # Called directly: the innermost sink keeps the assertion at its call, in the sink above it.
    assert props["L5_sanitized_inner"]["instances"] == ["a.c#middle"]
    assert "\\called == inner ==>" in props["L5_sanitized_inner"]["acsl"]
    # Two sinks that only reach each other: one keeps its property, so the bytes are still checked.
    cycle = model(
        functions, edges=[("a.c#user", "a.c#outer"), ("a.c#outer", "a.c#middle"), ("a.c#middle", "a.c#outer")]
    )
    props = by_name(sp.generate(cycle, threat(output_sinks=sinks[:2])))
    middle = props["L5_sanitized_middle"]
    assert middle["instances"] == ["a.c#outer"] and "forwarded_to" not in middle
    assert props["L5_sanitized_outer"]["forwarded_to"] == ["middle"]


@pytest.mark.unit
def test_a_sink_called_through_a_pointer_is_checked_as_its_precondition():
    """MetAcsl cannot name the arguments of an indirect call: a \\calling instance there never proves."""
    functions = {
        "a.c#log_line": fn("log_line", formals=[{"name": "msg", "kind": "const_pointer"}]),
        "a.c#report": fn("report"),
        "a.c#direct": fn("direct"),
    }
    m = _graph(functions, direct=[("a.c#direct", "a.c#log_line")], sites=[("a.c#report", "logger", ["a.c#log_line"])])
    prop = by_name(sp.generate(m, threat(output_sinks=[LOG_SINK])))["L5_sanitized_log_line"]
    assert "\\targets({log_line}), \\context(\\precond)" in prop["acsl"]
    assert "\\fguard(no_crlf_string(\\formal(msg)))" in prop["acsl"]
    assert prop["instances"] == ["a.c#direct", "a.c#report"]
    assert any("`calls` annotation naming log_line" in n for n in prop["notes"])
    # Called directly only: the assertion at each call, as before.
    m = _graph(functions, direct=[("a.c#direct", "a.c#log_line")])
    prop = by_name(sp.generate(m, threat(output_sinks=[LOG_SINK])))["L5_sanitized_log_line"]
    assert "\\context(\\calling)" in prop["acsl"] and "no_crlf_string(\\called_arg(msg))" in prop["acsl"]
    assert prop["instances"] == ["a.c#direct"] and prop["notes"] == []


@pytest.mark.unit
def test_the_seed_gives_the_callers_of_a_forwarding_sink_no_l5_unit(run_dir):
    m = _modbus_model()
    doc = sp.generate(m, threat(output_sinks=[FORWARD_WRAPPER, FORWARD_INNER]))
    _seed_one_file(run_dir, m, doc)
    units = _ledger_units(run_dir)
    assert [c for c in units if c.endswith("::l5_sanitized")] == ["m.c#send_msg::l5_sanitized"]
    assert units["m.c#send_msg::l5_sanitized"]["bookkeeping"]["security_properties"] == ["L5_sanitized_tcp_send"]


def _forward_wp(target: Path, run: Path, function: str, defs: str = "") -> dict:
    """run_wp_function.py on one function of the forwarding fixture, in the image, on this tree's pipeline."""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{target.resolve()}:/target:ro", "-v", f"{run.resolve()}:/framac-run", "-w", "/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
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


def _named_goals(report: dict, name: str) -> tuple[list[dict], list[dict]]:
    """(proven, unproven) goals of a WP report that carry the property's name."""
    mine = f"{name}:"
    proven = [g for g in report["layer_goals"] if str(g.get("annotation") or "").startswith(mine)]
    unproven = [g for g in report["unproven_goals"] if str(g.get("annotation") or "").startswith(mine)]
    return proven, unproven


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case", ["forwarded", "violated", "no_calls", "wrapper_alone"])
def test_forwarding_sink_acceptance_in_the_image(model_run, tmp_path, monkeypatch, case):  # noqa: F811
    """
    The libmodbus shape (forward/l5_forwarding.c) against the real model, MetAcsl and WP. With the
    wrapper and the transmitting sink declared, the wrapper's caller has no L5 goal and proves, and
    the transmitting sink's property proves in the wrapper, after the backend completed the buffer
    (`forwarded`); it stays unproven when the wrapper skips the completion (`violated`). Without a
    `calls` annotation at the pointer call, WP has no precondition to prove there: the run is
    flagged unsound and the ledger credits nothing (`no_calls`). Declared alone, the wrapper is
    still checked at its callers, one step too early: the goal is unproven on the correct program
    (`wrapper_alone`, the placement the forwarding replaces).
    """
    violate = case in ("violated", "no_calls")
    defs = {"violated": " -DVIOLATE", "no_calls": " -DVIOLATE -DNO_CALLS"}.get(case, "")
    sinks = [FORWARD_WRAPPER] if case == "wrapper_alone" else [FORWARD_WRAPPER, FORWARD_INNER]
    target = _one_file_target(tmp_path / "target", FORWARD_DIR / "l5_forwarding.c", {"output_sinks": sinks}, violate)
    (target / "Makefile").write_text(_VARIANT_MAKEFILE.format(defs=defs.strip()), encoding="utf-8", newline="\n")
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    # The model resolves the wrapper's call of the backend's send by type.
    assert ("(ctx->backend)->send", ["prog.c#tcp_send"]) in [(s["expr"], s["candidates"]) for s in m["indirect_sites"]]
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert not sp.validate(doc), sp.validate(doc)
    assert _sink_warnings(doc) == []
    props = by_name(doc)
    write_json(run / "workspace/reports/security_props.json", doc)
    if case == "wrapper_alone":
        assert props["L5_sanitized_send_msg"]["instances"] == ["prog.c#write_register"]
        proven, unproven = _named_goals(_forward_wp(target, run, "write_register"), "L5_sanitized_send_msg")
        assert unproven and not proven, (proven, unproven)
        return
    wrapper, inner = props["L5_sanitized_send_msg"], props["L5_sanitized_tcp_send"]
    assert wrapper["instances"] == [] and wrapper["forwarded_to"] == ["tcp_send"]
    assert inner["instances"] == ["prog.c#send_msg"] and "\\context(\\precond)" in inner["acsl"]
    assert not [o for o in doc["obligations"].get("prog.c#write_register", []) if o["class"] == "l5_sanitized"]
    monkeypatch.chdir(run)
    _seed_one_file(run, m, doc)
    assert [c for c in _ledger_units(run) if c.endswith("::l5_sanitized")] == ["prog.c#send_msg::l5_sanitized"]
    report = _forward_wp(target, run, "send_msg", defs)
    assert report["security_props"]["properties"] == ["L5_sanitized_tcp_send"]
    proven, unproven = _named_goals(report, "L5_sanitized_tcp_send")
    detail = json.dumps({"proven": proven, "unproven": unproven, "log": report.get("wp_log_tail")}, indent=1)
    if case == "no_calls":
        # No goal carries the property, and nothing may read that as "decided statically".
        assert not proven and not unproven, detail
        assert report["status"] != "all_proven" and not report["soundness"]["ok"], report["soundness"]
        L.cmd_ingest_wp([run / "workspace/reports/wp/send_msg.json"])
        unit = _ledger_units(run)["prog.c#send_msg::l5_sanitized"]
        assert unit["status"] != "covered" and unit["evidence"][-1]["result"] == "wp_no_credited_goals", unit
        return
    if violate:
        assert unproven and not proven, detail
        return
    assert proven and not unproven, detail
    # The caller loads no property and proves: nothing is asked of it before the buffer is complete.
    caller = _forward_wp(target, run, "write_register")
    assert not caller.get("security_props") and "l5_sanitized" not in caller["by_obligation_class"]
    assert caller["status"] == "all_proven", caller.get("wp_log_tail")


INIT_DIR = FIX / "initializer"
INIT_LISTS = {
    "secrets": [{"name": "key", "kind": "global", "description": "d"}],
    "output_sinks": [{"function": "net_send", "kind": "network", "params": ["buf"], "length": "n", "description": "d"}],
}


INIT_GATE = {"function": "login", "state": "auth_ok", "protects": ["login"], "description": "d"}
INIT_STRONG = {
    "name": "auth_range",
    "variant": "strong",
    "predicate": "0 <= auth_ok <= 1",
    "scope": ["h_init", "h_assign"],
    "description": "d",
}
# What scripts/phase0_model.py must do for package E and does not yet (it is not a file of package
# D1): carry the dump's `initializer` flag of a call into the model's call site. The image test
# applies this one-line change to a copy of scripts/ and mounts the copy.
PASSTHROUGH_FROM = '"literals": dict(lits)})'
PASSTHROUGH_TO = '"literals": dict(lits), **({"initializer": bool(c["initializer"])} if "initializer" in c else {})})'


def _init_model() -> dict:
    """local_init.c as the model would give it: every `_init` function calls in an initializer."""

    def site(callee: str, line: int, init: bool) -> dict:
        return {"callee": callee, "line": line, "literals": {}, "initializer": init}

    send = [{"name": "fd", "kind": "value"}, {"name": "buf", "kind": "const_pointer"}, {"name": "n", "kind": "value"}]
    functions = {
        "prog.c#f_assign": fn("f_assign", "prog.c", external_calls=["net_send"], call_sites=[site("net_send", 56, False)]),
        "prog.c#f_init": fn("f_init", "prog.c", external_calls=["net_send"], call_sites=[site("net_send", 64, True)]),
        "prog.c#g_assign": fn("g_assign", "prog.c", external_calls=["net_send"], call_sites=[site("net_send", 71, False)]),
        "prog.c#g_init": fn("g_init", "prog.c", external_calls=["net_send"], call_sites=[site("net_send", 77, True)]),
        "prog.c#h_assign": fn("h_assign", "prog.c", external_calls=["fill"], call_sites=[site("fill", 84, False)]),
        "prog.c#h_init": fn("h_init", "prog.c", external_calls=["fill"], call_sites=[site("fill", 90, True)]),
        "prog.c#login": fn("login", "prog.c", writes={"pointer": 0, "params": [], "globals": ["auth_ok"]}),
    }  # fmt: skip
    return model(
        functions,
        external_formals={"net_send": send, "fill": [{"name": "out", "kind": "pointer"}]},
        external_decls={
            "net_send": {
                "decl": "prog.c:16",
                "proto": "int net_send(int fd, char const *buf, unsigned long n);",
                "signature": "int(int,char const *,unsigned long)",
            },
            "fill": {"decl": "prog.c:18", "proto": "int fill(int *out);", "signature": "int(int *)"},
        },
        global_variables={
            "auth_ok": {"name": "auth_ok", "file": "prog.c", "type": "int"},
            "key": {"name": "key", "file": "prog.c", "type": "char[16]"},
        },
    )


def _init_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copy(INIT_DIR / "local_init.c", tree / "prog.c")
    return tree


def _init_doc(tree: Path, **lists) -> dict:
    block = {**INIT_LISTS, "auth_gates": [INIT_GATE], "invariants": [INIT_STRONG], **lists}
    return sp.generate(_init_model(), threat(**block), roots=[tree])


@pytest.mark.unit
def test_the_fixture_lines_of_the_initializer_model_are_the_real_ones():
    lines = (INIT_DIR / "local_init.c").read_text(encoding="utf-8").splitlines()
    for rec in _init_model()["functions"].values():
        for s in rec.get("call_sites", []):
            assert f"{s['callee']}(" in lines[s["line"] - 1], (rec["name"], lines[s["line"] - 1])
            assert ("int n =" in lines[s["line"] - 1] or "int r =" in lines[s["line"] - 1]) is s["initializer"]
    decls = _init_model()["external_decls"]
    assert "net_send(" in lines[15] and "fill(" in lines[17] and decls["fill"]["decl"] == "prog.c:18"


@pytest.mark.unit
def test_an_initializer_call_gets_an_in_code_check_per_skipped_context(tmp_path):
    """
    Package E: MetAcsl generates no \\calling, \\writing or \\strong_invariant instance at a call placed
    in an initializer. Each property whose context is skipped there lists an in-code check at the
    site, and keeps its MetAcsl text for the statement calls.
    """
    doc = _init_doc(_init_tree(tmp_path))
    assert not sp.validate(doc), sp.validate(doc)
    props = by_name(doc)
    l5, l6, l4, inv = (
        props[n] for n in ("L5_sanitized_net_send", "L6_no_leak_key", "L4_auth_state_login", "L4_invariant_auth_range")
    )
    # A pointer argument is cast to its parameter's type: ACSL does not convert an array (`buf`) itself.
    sent = "/*@ check L5_sanitized_net_send: \\initialized(((char const *)${arg1}) + (0 .. ${arg2} - 1)); */"
    assert [(c["function"], c["line"], c["at"], c["check"]) for c in l5["init_checks"]] == [
        ("prog.c#f_init", 64, "before", sent),
        ("prog.c#g_init", 77, "before", sent),
    ]
    assert [(c["function"], c["check"]) for c in l6["init_checks"]] == [
        ("prog.c#f_init", "/*@ check L6_no_leak_key: \\separated(((char const *)${arg1}), &key); */"),
        ("prog.c#g_init", "/*@ check L6_no_leak_key: \\separated(((char const *)${arg1}), &key); */"),
    ]
    # \writing: what the declared callee assigns (`assigns *out`, read at its declaration), with the
    # argument in place of the parameter. A caller of such a callee is an instance of the property.
    assert l4["instances"] == ["prog.c#h_assign", "prog.c#h_init"]
    assert [(c["function"], c["callee"], c["check"]) for c in l4["init_checks"]] == [
        ("prog.c#h_init", "fill", "/*@ check L4_auth_state_login: \\separated(((int *)${arg0}), &auth_ok); */")
    ]
    assert [(c["function"], c["at"], c["check"]) for c in inv["init_checks"]] == [
        ("prog.c#h_init", "after", "/*@ check L4_invariant_auth_range: 0 <= auth_ok <= 1; */")
    ]
    # The properties stay MetAcsl properties (unlike a `code` property): the statement calls need them.
    text, names, _ = sp.meta_file_text(doc, "prog.c#h_init")
    assert names == ["L4_auth_state_login", "L4_invariant_auth_range"] and "\\context(\\writing)" in text
    assert "already in the code there" in sp.brief_entries(doc, "prog.c", "f_init")[0]["discharge"]
    assert "already in the code there" not in sp.brief_entries(doc, "prog.c", "f_assign")[0]["discharge"]
    assert not [w for w in doc["warnings"] if "initializers" in w]


@pytest.mark.unit
def test_initializer_checks_go_into_the_work_tree_and_come_out_again(tmp_path):
    tree = _init_tree(tmp_path)
    original = (tree / "prog.c").read_text(encoding="utf-8")
    doc = _init_doc(tree)
    out = sp.apply_taint(doc, tree, taint=False)
    assert not out["skipped"] and not out["init_unplaced"], out
    # `index` tells the checks of one line apart: a report gives a check's line, not its name.
    assert [(c["line"], c["index"], c["property"]) for c in out["code_checks"]] == [
        (64, 0, "L5_sanitized_net_send"),
        (64, 1, "L6_no_leak_key"),
        (77, 0, "L5_sanitized_net_send"),
        (77, 1, "L6_no_leak_key"),
        (90, 0, "L4_auth_state_login"),
        (90, 1, "L4_invariant_auth_range"),
    ]
    lines = (tree / "prog.c").read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(original.splitlines())
    assert lines[76] == (
        "    /*@ check L5_sanitized_net_send: \\initialized(((char const *)(SENT)) + (0 .. (16) - 1)); */ "
        "/*@ check L6_no_leak_key: \\separated(((char const *)(SENT)), &key); */ int n = net_send(fd, SENT, 16);"
    )
    assert lines[89] == (
        "    /*@ check L4_auth_state_login: \\separated(((int *)(&FILLED)), &auth_ok); */ int r = fill(&FILLED);"
        "/*@ check L4_invariant_auth_range: 0 <= auth_ok <= 1; */ "
    )
    # The statement calls are MetAcsl's: nothing is written there.
    assert lines[70] == "    n = net_send(fd, SENT, 16);" and lines[83] == "    r = fill(&FILLED);"
    # A re-run leaves the same text, and a run without the properties removes the checks.
    assert sp.apply_taint(doc, tree, taint=False)["changed"] == []
    sp.apply_taint({"properties": []}, tree, taint=False)
    assert (tree / "prog.c").read_text(encoding="utf-8") == original


@pytest.mark.unit
def test_an_initializer_check_that_cannot_be_written_is_unchecked(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    source = (
        "extern int net_send(int fd, const char *buf, unsigned long n);\nchar key[16];\nchar *next(void);\n"
        "void a(int fd)\n{\n    int n = net_send(fd, next(), 16);\n    (void)n;\n}\n"
        "void b(int fd)\n{\n    int k = 0, n = net_send(fd, key, 16);\n    (void)(k + n);\n}\n"
        "void c(int fd)\n{\n    int n = SEND16(fd);\n    (void)n;\n}\n"
    )
    (tree / "prog.c").write_text(source, encoding="utf-8", newline="\n")
    m = _init_model()
    m["functions"] = {
        f"prog.c#{name}": fn(
            name,
            "prog.c",
            external_calls=["net_send"],
            call_sites=[{"callee": "net_send", "line": line, "literals": {}, "initializer": True}],
        )
        for name, line in (("a", 6), ("b", 11), ("c", 16))
    }
    doc = sp.generate(m, threat(**INIT_LISTS), roots=[tree])
    out = sp.apply_taint(doc, tree, taint=False)
    assert out["code_checks"] == [] and (tree / "prog.c").read_text(encoding="utf-8") == source
    assert sp.settle_init_checks(doc, out["init_unplaced"]) == 6
    assert not sp.validate(doc), sp.validate(doc)
    for name in ("L5_sanitized_net_send", "L6_no_leak_key"):
        prop = by_name(doc)[name]
        assert "init_checks" not in prop
        assert [(u["function"], u["reason"]) for u in prop["unchecked"]] == [
            ("prog.c#a", "an initializer call of net_send: an argument the check cannot repeat"),
            ("prog.c#b", "an initializer call of net_send: the call is not the whole initializer of one declaration"),
            ("prog.c#c", "an initializer call of net_send: no initializer call found on that line (a macro?)"),
        ]
    # A sink whose parameters the model does not know: no check can be written at all.
    del m["external_formals"]["net_send"]
    sink = {"function": "net_send", "kind": "network", "params": ["buf"], "description": "d"}
    prop = by_name(sp.generate(m, threat(output_sinks=[sink]), roots=[tree]))["L5_sanitized_net_send"]
    assert "init_checks" not in prop and len(prop["unchecked"]) == 3
    reason = "an initializer call of net_send: the sink's parameters or their types are unknown"
    assert prop["unchecked"][0]["reason"] == reason
    # The same when the model has the parameters without their types: the check would not type on an
    # array argument, and an annotation that does not type stops the function's whole WP run.
    m = _init_model()
    del m["external_decls"]["net_send"]["signature"]
    prop = by_name(sp.generate(m, threat(output_sinks=[sink]), roots=[tree]))["L5_sanitized_net_send"]
    assert "init_checks" not in prop and {u["reason"] for u in prop["unchecked"]} == {reason}
    # A `void *` parameter is its bytes; a function-pointer parameter takes no cast.
    m["external_decls"]["net_send"]["signature"] = "int(void (*)(int),void const * restrict,unsigned long)"
    m["external_formals"]["net_send"][0]["kind"] = "pointer"
    assert m["external_formals"]["net_send"][0]["name"] == "fd"
    assert sp._Model(m).arg_refs("net_send") == {"fd": "${arg0}", "buf": "((char const *)${arg1})", "n": "${arg2}"}


@pytest.mark.unit
def test_a_model_without_initializer_flags_says_so():
    m = _init_model()
    for rec in m["functions"].values():
        for s in rec.get("call_sites", []):
            del s["initializer"]
    doc = sp.generate(m, threat(**INIT_LISTS))
    assert [w for w in doc["warnings"] if "do not say which calls are initializers" in w]
    assert all("init_checks" not in p for p in doc["properties"])
    # Without a threat model there is nothing a missing flag could hide.
    assert not [w for w in sp.generate(m, None)["warnings"] if "initializers" in w]


# ---------------------------------------------------------------------------------------------------
# Assets, invariants and call rules (package D1 of docs/plans/metacsl-exploitation-plan.md)
# ---------------------------------------------------------------------------------------------------

CONF_FORMALS = [{"name": "c", "kind": "pointer"}, {"name": "m", "kind": "value"}]
KIND_ASSET = {"name": "config", "lvalue": "config", "writers": ["set_config"], "description": "d"}

# variant -> (function under WP, property name, threat-model lists), as TEMPLATE_VARIANTS.
KIND_VARIANTS: dict[str, tuple[str, str, dict]] = {
    "l3_writers_global": ("store", "L3_writers_config", {"assets": [KIND_ASSET]}),
    "l3_writers_formal": (
        "bump",
        "L3_writers_mode",
        {
            "assets": [
                {"name": "mode", "lvalue": "c->mode", "params": ["s"], "writers": ["set_mode"], "description": "d"}
            ]
        },
    ),
    "l3_readers_global": (
        "peek",
        "L3_readers_pin",
        {
            "assets": [
                {"name": "pin", "lvalue": "pin", "writers": ["set_pin"], "readers": ["check_pin"], "description": "d"}
            ]
        },
    ),
    "l3_readers_formal": (
        "peek",
        "L3_readers_token",
        {
            "assets": [
                {
                    "name": "token",
                    "lvalue": "c->token",
                    "params": ["s"],
                    "writers": ["set_token"],
                    "readers": ["use_token"],
                    "description": "d",
                }
            ]
        },
    ),
    "l4_invariant_weak": (
        "add",
        "L4_invariant_count_bound",
        {
            "invariants": [
                {
                    "name": "count_bound",
                    "variant": "weak",
                    "predicate": "count <= limit",
                    "scope": ["add"],
                    "description": "d",
                }
            ]
        },
    ),
    "l4_invariant_strong": (
        "step",
        "L4_invariant_level_range",
        {
            "invariants": [
                {
                    "name": "level_range",
                    "variant": "strong",
                    "predicate": "0 <= level <= 3",
                    "scope": ["step"],
                    "description": "d",
                }
            ]
        },
    ),
    "l4_invariant_conditional": (
        "handle",
        "L4_invariant_depth_bound",
        {
            "invariants": [
                {
                    "name": "depth_bound",
                    "variant": "conditional",
                    "predicate": "depth <= 8",
                    "scope": ["handle"],
                    "description": "d",
                }
            ]
        },
    ),
    "l4_invariant_monotonic": (
        "advance",
        "L4_invariant_phase_up",
        {"invariants": [{"name": "phase_up", "variant": "monotonic", "lvalue": "phase", "description": "d"}]},
    ),
    "l4_invariant_monotonic_formal": (
        "advance",
        "L4_invariant_phase_up",
        {"invariants": [{"name": "phase_up", "variant": "monotonic", "lvalue": "c->phase", "description": "d"}]},
    ),
    "l4_call_global": (
        "work",
        "L4_call_use_dev",
        {"call_rules": [{"function": "use_dev", "predicate": "ready != 0", "description": "d"}]},
    ),
    "l4_call_formal": (
        "poke",
        "L4_call_write_reg",
        {"call_rules": [{"function": "write_reg", "predicate": "idx < 8", "description": "d"}]},
    ),
    "l4_call_entry": (
        "poke",
        "L4_call_write_reg",
        {"call_rules": [{"function": "write_reg", "predicate": "idx < 8", "description": "d"}]},
    ),
}
# The template variant each program exercises (`variant` of its property).
KIND_VARIANT_OF = {
    "l3_writers_global": "global",
    "l3_writers_formal": "formal",
    "l3_readers_global": "global",
    "l3_readers_formal": "formal",
    "l4_invariant_weak": "weak",
    "l4_invariant_strong": "strong",
    "l4_invariant_conditional": "conditional",
    "l4_invariant_monotonic": "monotonic",
    "l4_invariant_monotonic_formal": "monotonic_formal",
    "l4_call_global": "global",
    "l4_call_formal": "formal",
    "l4_call_entry": "entry",
}


def _kinds_model() -> dict:
    functions = {
        "a.c#set_config": fn("set_config", writes={"pointer": 0, "params": [], "globals": ["config"]}),
        "a.c#store": fn(
            "store",
            formals=[{"name": "out", "kind": "pointer"}],
            writes={"pointer": 1, "params": ["out"], "globals": []},
        ),
        "a.c#set_mode": fn("set_mode", formals=CONF_FORMALS, writes={"pointer": 1, "params": ["c"], "globals": []}),
        "a.c#bump": fn(
            "bump", formals=[{"name": "s", "kind": "pointer"}], writes={"pointer": 1, "params": ["s"], "globals": []}
        ),
        "a.c#read_mode": fn("read_mode", formals=[{"name": "c", "kind": "const_pointer"}]),
        "a.c#add": fn("add", writes={"pointer": 0, "params": [], "globals": ["count"]}),
        "a.c#run": fn("run"),
        "a.c#work": fn("work", external_calls=["use_dev"]),
        "a.c#write_reg": fn("write_reg", formals=[{"name": "idx", "kind": "value"}, {"name": "v", "kind": "value"}]),
        "a.c#poke": fn("poke"),
    }
    return model(
        functions,
        edges=[("a.c#run", "a.c#add"), ("a.c#poke", "a.c#write_reg")],
        external_formals={"use_dev": [{"name": "v", "kind": "value"}]},
        global_variables={
            n: {"name": n, "file": "a.c", "type": "int"} for n in ("config", "count", "limit", "ready", "phase")
        },
    )


def _inv(variant: str, **extra) -> dict:
    base = {"name": "count_bound", "variant": variant, "description": "d"}
    if variant != "monotonic":
        base["predicate"] = "count <= limit"
    return {**base, **extra}


@pytest.mark.unit
def test_assets_invariants_and_call_rules_become_properties():
    lists = {
        "assets": [
            {**KIND_ASSET, "readers": ["read_mode"]},
            {"name": "mode", "lvalue": "c->mode", "params": ["s"], "writers": ["set_mode"], "description": "d"},
        ],
        "invariants": [
            _inv("weak", scope=["add"]),
            _inv("conditional", name="entry_bound", scope=["add"]),
            _inv("monotonic", name="phase_up", lvalue="phase", direction="down"),
        ],
        "call_rules": [
            {"function": "use_dev", "predicate": "ready != 0 && v >= 0", "description": "d"},
            {"function": "write_reg", "predicate": "idx < 8", "description": "d"},
        ],
    }
    doc = sp.generate(_kinds_model(), threat(**lists))
    assert not sp.validate(doc), sp.validate(doc)
    assert doc["warnings"] == [], doc["warnings"]
    props = by_name(doc)
    assert {n: (p["kind"], p["obligation_class"], p["layer"], p["variant"]) for n, p in props.items()} == {
        "L3_writers_config": ("asset_writers", "l3_isolation", 3, "global"),
        "L3_readers_config": ("asset_readers", "l3_isolation", 3, "global"),
        "L3_writers_mode": ("asset_writers", "l3_isolation", 3, "formal"),
        "L4_invariant_count_bound": ("invariant", "l4_invariant", 4, "weak"),
        "L4_invariant_entry_bound": ("invariant", "l4_invariant", 4, "conditional"),
        "L4_invariant_phase_up": ("invariant", "l4_invariant", 4, "monotonic"),
        "L4_call_use_dev": ("call_rule", "l4_call_rule", 4, "formal"),
        "L4_call_write_reg": ("call_rule", "l4_call_rule", 4, "formal"),
    }
    writers = props["L3_writers_config"]
    assert "\\targets(\\diff(\\ALL, {set_config})), \\context(\\writing)" in writers["acsl"]
    assert "\\separated(\\written, &config)" in writers["acsl"]
    # The functions that write through a pointer, and the direct writers that are not declared.
    assert writers["instances"] == ["a.c#bump", "a.c#set_mode", "a.c#store"] and writers["sources"] == ["a.c"]
    # One clause per parameter name the object is passed as.
    mode = props["L3_writers_mode"]["acsl"]
    assert "\\tguard(\\separated(\\written, &\\formal(c)->mode)) &&" in mode
    assert "\\tguard(\\separated(\\written, &\\formal(s)->mode))" in mode
    readers = props["L3_readers_config"]
    assert "\\targets(\\diff(\\ALL, {read_mode})), \\context(\\reading)" in readers["acsl"]
    assert "a.c#read_mode" not in readers["instances"] and len(readers["instances"]) == 9
    # A weak invariant's `requires` is proved in the callers; a conditional one asks nothing of them.
    assert props["L4_invariant_count_bound"]["instances"] == ["a.c#add", "a.c#run"]
    assert (
        "\\targets({add}), \\context(\\weak_invariant),\n      count <= limit;"
        in props["L4_invariant_count_bound"]["acsl"]
    )
    assert props["L4_invariant_entry_bound"]["instances"] == ["a.c#add"]
    assert "\\context(\\conditional_invariant)" in props["L4_invariant_entry_bound"]["acsl"]
    mono = props["L4_invariant_phase_up"]
    assert "\\separated(\\written, &phase) || \\at(phase, Before) >= \\at(phase, After);" in mono["acsl"]
    assert "\\targets(\\ALL), \\context(\\writing)" in mono["acsl"]
    # A parameter of the callee is the argument of the call; a global stays as written.
    assert (
        "\\tguard(\\called == use_dev ==> \\fguard(ready != 0 && \\called_arg(v) >= 0));"
        in props["L4_call_use_dev"]["acsl"]
    )
    assert props["L4_call_use_dev"]["instances"] == ["a.c#work"]
    assert props["L4_call_write_reg"]["instances"] == ["a.c#poke"]
    # `add` reads like any function (the readers property), and holds the two invariants.
    assert {o["class"] for o in doc["obligations"]["a.c#add"]} == {"l3_isolation", "l4_invariant"}
    assert doc["summary"]["functions_by_class"]["l3_isolation"] == 9
    # Every generated text is pure ACSL and passes the guard of package R.
    for p in doc["properties"]:
        assert not sp.meta_text_problems(p["acsl"])
        kinds = {t.kind for t in tokenize_c_acsl(p["acsl"], p["name"])}
        assert kinds <= {"acsl_block", "whitespace"}, (p["name"], kinds)
    entry = [e for e in sp.brief_entries(doc, "a.c", "add") if e["property"].startswith("L4_")]
    assert [e["property"] for e in entry] == ["L4_invariant_count_bound", "L4_invariant_entry_bound"]
    assert "requires L4_invariant_count_bound: meta:" in entry[0]["discharge"]
    assert "behavior `L4_invariant_entry_bound`" in entry[1]["discharge"]


@pytest.mark.unit
def test_a_callee_called_through_a_pointer_gets_the_call_rule_as_its_precondition():
    m = _kinds_model()
    m["edges"].append({"caller": "a.c#run", "callee": "a.c#write_reg", "kind": "indirect"})
    rule = {"function": "write_reg", "predicate": "idx < 8", "description": "d"}
    prop = by_name(sp.generate(m, threat(call_rules=[rule])))["L4_call_write_reg"]
    assert prop["variant"] == "entry" and prop["instances"] == ["a.c#poke", "a.c#run"]
    assert "\\targets({write_reg}), \\context(\\precond),\n      \\fguard(\\formal(idx) < 8);" in prop["acsl"]
    assert "calls" in sp.brief_entries({"properties": [prop], "obligations": {}}, "a.c", "poke")[0]["discharge"]


@pytest.mark.unit
def test_a_monotonic_invariant_is_not_for_eva():
    """R, item 1: Eva does not evaluate \\at(x, Before). The property says which engines may load it."""
    lists = {"invariants": [_inv("monotonic", name="phase_up", lvalue="phase"), _inv("weak", scope=["add"])]}
    m = _kinds_model()
    m["functions"]["a.c#advance"] = fn("advance", writes={"pointer": 0, "params": [], "globals": ["phase"]})
    doc = sp.generate(m, threat(**lists))
    props = by_name(doc)
    assert props["L4_invariant_phase_up"]["engines"] == ["eacsl"] and "engines" not in props["L4_invariant_count_bound"]
    assert "a.c#advance" in props["L4_invariant_phase_up"]["instances"]
    both = sp.module_meta_file_text(doc)
    eva = sp.module_meta_file_text(sp.for_engine(doc, "eva"))
    eacsl = sp.module_meta_file_text(sp.for_engine(doc, "eacsl"))
    assert both and eva and eacsl
    assert both[1] == eacsl[1] == ["L4_invariant_phase_up", "L4_invariant_count_bound"]
    assert eva[1] == ["L4_invariant_count_bound"] and "\\at(" not in eva[0]


@pytest.mark.unit
def test_an_invariant_is_bounded_by_its_scope():
    m = _kinds_model()
    for i in range(60):
        m["functions"][f"a.c#f{i}"] = fn(f"f{i}")
    doc = sp.generate(m, threat(invariants=[_inv("strong")]))
    prop = by_name(doc)["L4_invariant_count_bound"]
    assert len(prop["instances"]) == 70 and "\\targets(\\ALL)" in prop["acsl"]
    assert [w for w in doc["warnings"] if "70 functions carry a unit of this invariant" in w and "scope" in w]
    scoped = sp.generate(m, threat(invariants=[_inv("strong", scope=["add", "f1"])]))
    assert by_name(scoped)["L4_invariant_count_bound"]["instances"] == ["a.c#add", "a.c#f1", "a.c#run"]
    assert "\\targets({add, f1})" in by_name(scoped)["L4_invariant_count_bound"]["acsl"]
    assert scoped["warnings"] == []


@pytest.mark.unit
def test_unusable_new_items_warn_and_generate_nothing():
    cases = [
        ({"assets": [{**KIND_ASSET, "lvalue": "nowhere"}]}, "neither a global of the build nor a parameter"),
        ({"assets": [{**KIND_ASSET, "lvalue": "c"}]}, "is a parameter itself"),
        ({"invariants": [_inv("conditional")]}, "needs a `scope`"),
        ({"invariants": [_inv("weak", scope=["absent"])]}, "no function of its scope"),
        ({"invariants": [_inv("monotonic", predicate="count <= limit", lvalue="phase")]}, "no `predicate`"),
        ({"invariants": [_inv("weak", predicate="count <= limit; */")]}, "holds `*/`"),
        ({"invariants": [_inv("weak", predicate="\\result == 0")]}, "holds `\\result`"),
        ({"call_rules": [{"function": "use_dev", "predicate": "ready, \\flags(proof:axiom)"}]}, "holds `\\flags`"),
        ({"call_rules": [{"function": "absent", "predicate": "ready != 0"}]}, "neither a function of the build"),
    ]
    for lists, expected in cases:
        doc = sp.generate(_kinds_model(), threat(**lists))
        assert doc["properties"] == [] and [w for w in doc["warnings"] if expected in w], (lists, doc["warnings"])
    # A name that is neither a parameter of the callee nor a global is said (a misspelt parameter
    # would otherwise be read as a global that does not exist).
    rule = {"function": "write_reg", "predicate": "index < 8", "description": "d"}
    doc = sp.generate(_kinds_model(), threat(call_rules=[rule]))
    assert [w for w in doc["warnings"] if "names index, which is neither a parameter of write_reg nor a global" in w]
    # A parameter name no function has would make its clause \true everywhere: it is left out.
    asset = {"name": "mode", "lvalue": "c->mode", "params": ["ctxx"], "writers": ["set_mode"], "description": "d"}
    doc = sp.generate(_kinds_model(), threat(assets=[asset]))
    assert "\\formal(ctxx)" not in by_name(doc)["L3_writers_mode"]["acsl"]
    assert [w for w in doc["warnings"] if "ctxx is neither a global" in w and "left out" in w]


@pytest.mark.unit
def test_no_generated_text_holds_what_package_r_rules_out(tmp_path):
    """
    R's constraints: no \\inter or \\in_file in \\targets, no proof:deduce or proof:axiom flag, no
    \\result under \\tguard. The guard holds whatever a template says.
    """
    ok = "/*@ meta \\prop, \\name(P), \\targets(\\diff(\\ALL, {f})), \\context(\\writing), \\separated(\\written, &x);\n*/"
    assert sp.meta_text_problems(ok) == []
    bad = {
        "\\targets(\\inter({a, b}, {b}))": "\\inter in \\targets",
        '\\targets(\\in_file("a.c"))': "\\in_file in \\targets",
        "\\flags(proof:deduce)": "proof:deduce",
        "\\flags(proof : axiom)": "proof:axiom",
        "\\tguard(\\result != 0 ==> x == \\old(x))": "\\result under \\tguard",
    }
    for text, expected in bad.items():
        problems = sp.meta_text_problems(f"/*@ meta \\prop, \\name(P), {text}, \\context(\\writing), x == 0; */")
        assert len(problems) == 1 and expected in problems[0], (text, problems)
    # \result outside a \tguard is MetAcsl's to refuse (it says so); under one it would be silent.
    assert (
        sp.meta_text_problems("/*@ meta \\prop, \\name(P), \\targets({f}), \\context(\\postcond), \\result == 0; */")
        == []
    )
    # A template that asks for a deduction is not rendered into a property.
    templates = tmp_path / "metacsl"
    shutil.copytree(ROOT / "templates" / "metacsl", templates)
    text = (templates / "l4_call_rule.acsl").read_text(encoding="utf-8")
    text = text.replace("\\context(\\calling),", "\\context(\\calling), \\flags(proof:deduce),")
    (templates / "l4_call_rule.acsl").write_text(text, encoding="utf-8", newline="\n")
    rule = {"function": "use_dev", "predicate": "ready != 0", "description": "d"}
    doc = sp.generate(_kinds_model(), threat(call_rules=[rule]), sp._Templates(templates))
    assert doc["properties"] == []
    assert [w for w in doc["warnings"] if "L4_call_use_dev: not generated" in w and "proof:deduce" in w]
    for name in ("l3_asset", "l4_invariant", "l4_call_rule", "l4_auth_state", "l5_sanitized", "l6_no_leak", "l6_wiped"):
        body = "\n".join(sp.load_template(name).values())
        assert "\\inter" not in body and "\\in_file" not in body and "proof:" not in body, name


@pytest.mark.unit
def test_threat_model_schema_takes_the_new_lists(tmp_path):
    path = tmp_path / "THREAT_MODEL.md"

    def status(**lists) -> tuple[str, list]:
        block = {"schema_version": 1, "input_sources": [], "secrets": [], "auth_gates": [], "output_sinks": []}
        block.update(lists)
        path.write_text(f"# Threat model\n\n```json framac-threat-model\n{json.dumps(block)}\n```\n", encoding="utf-8")
        loaded = trust.load_threat_model(path)
        return loaded["status"], loaded.get("errors") or []

    # The lists are optional: a threat model without them is what it was.
    assert status()[0] == "ok"
    for variant, (_, _, lists) in KIND_VARIANTS.items():
        assert status(**lists) == ("ok", []), variant
    rule = {"function": "use_dev", "description": "d"}
    for predicate in (
        "ready != 0; */ /*@ assert \\false",
        "ready /* x */ != 0",
        "ready != 0 // x",
        "\\result == 0",
        "ready != 0, \\flags(proof:deduce)",
        "proof:axiom",
        "\\tguard(ready != 0)",
        "",
    ):
        assert status(call_rules=[{**rule, "predicate": predicate}])[0] == trust.STATUS_INVALID, predicate
        assert status(invariants=[_inv("weak", predicate=predicate)])[0] == trust.STATUS_INVALID, predicate
        assert sp.predicate_problem(predicate), predicate
    for predicate in ("ready != 0", "\\valid(buf + (0 .. len - 1)) && len <= 64", "s->n < 8 ? a[0] == 1 : \\true"):
        assert status(call_rules=[{**rule, "predicate": predicate}]) == ("ok", []), predicate
        assert sp.predicate_problem(predicate) is None
    # What the schema cannot say: which fields go with which variant.
    for item, expected in (
        (_inv("monotonic"), "needs an `lvalue`"),
        (_inv("monotonic", lvalue="phase", predicate="count <= limit"), "takes no `predicate`"),
        (_inv("weak", predicate=None), "needs a `predicate`"),
        (_inv("weak", lvalue="phase"), "`lvalue` and `direction` go with the monotonic variant"),
        (_inv("conditional"), "needs a `scope`"),
    ):
        item = {k: v for k, v in item.items() if v is not None}
        found = status(invariants=[item])
        assert found[0] == trust.STATUS_INVALID and [e for e in found[1] if expected in e], (item, found)
    assert status(assets=[{**KIND_ASSET, "lvalue": "a[0]"}])[0] == trust.STATUS_INVALID
    assert status(invariants=[_inv("sometimes")])[0] == trust.STATUS_INVALID


@pytest.mark.unit
def test_check_threat_model_checks_the_new_names_against_the_model(tmp_path, capsys):
    lists = {
        "assets": [
            {"name": "config", "lvalue": "konfig", "writers": ["set_config", "set_konfig"], "description": "d"},
            {"name": "mode", "lvalue": "c->mode", "params": ["zz"], "writers": [], "readers": ["nobody"], "description": "d"},
        ],
        "invariants": [
            _inv("weak", scope=["add", "sub"]),
            _inv("monotonic", name="up", lvalue="faze"),
            _inv("strong", name="other", predicate="kount <= limit"),
        ],
        "call_rules": [
            {"function": "use_dev", "predicate": "ready != 0 && v > 0", "description": "d"},
            {"function": "write_reg", "predicate": "index < 8", "description": "d"},
            {"function": "use_dv", "predicate": "ready != 0", "description": "d"},
        ],
    }  # fmt: skip
    block = {"schema_version": 1, "input_sources": [], "secrets": [], "auth_gates": [], "output_sinks": [], **lists}
    path = tmp_path / "THREAT_MODEL.md"
    path.write_text(f"# Threat model\n\n```json framac-threat-model\n{json.dumps(block)}\n```\n", encoding="utf-8")
    m = _kinds_model()
    m["externals"] = ["use_dev"]
    write_json(tmp_path / "model.json", m)
    capsys.readouterr()
    assert trust.main(["check-threat-model", str(path), "--model", str(tmp_path / "model.json")]) == 0
    warnings = json.loads(capsys.readouterr().out)["warnings"]
    assert warnings == [
        "threat model: assets config: lvalue konfig starts at konfig, which is neither a global of the build nor a "
        "parameter of one of its functions",
        "threat model: assets config names set_konfig, which is not a function of the build",
        "threat model: assets mode: params names zz, which is not a parameter of any function of the build",
        "threat model: assets mode names nobody, which is not a function of the build",
        "threat model: invariants count_bound names sub, which is not a function of the build",
        "threat model: invariants up: lvalue faze starts at faze, which is neither a global of the build nor a "
        "parameter of one of its functions",
        "threat model: invariants other: the predicate names kount, which is not a global of the build",
        "threat model: call_rules write_reg: the predicate names index, which is neither a parameter of write_reg "
        "nor a global of the build",
        "threat model: call_rules names use_dv, which is neither a function of the build nor called by one",
    ]


# -- declared callees: what a \writing property takes from their assigns ----------------------------

_PLAT_HEADER = """/* platform functions the target only declares */
/*@ assigns *out \\from \\nothing; */
extern int fill(int *out);
/*@ requires \\valid(a) && \\valid(b);
    assigns \\union(*a, *b); */
extern void two(int *a, int *b);
/*@ assigns {*a, *b} \\from \\nothing; */
extern void pair(int *a,
                 int *b);
extern void bare(int *p);
/*@ assigns \\result \\from \\union(x, y); assigns \\nothing; */ extern int pure(int x, int y);
/*@ assigns *p, errno \\from n; */
extern void both(int *p, int n);
"""


@pytest.mark.unit
def test_the_assigns_of_a_declared_function_are_read_at_its_declaration():
    def at(name: str) -> dict:
        line = next(i for i, text in enumerate(_PLAT_HEADER.splitlines(), 1) if f" {name}(" in text)
        return sp.contract_assigns(_PLAT_HEADER, line, name)

    assert at("fill") == {"status": "listed", "terms": ["*out"]}
    assert at("two")["status"] == "set" and at("pair")["status"] == "set"
    assert at("bare") == {"status": "none", "terms": []}
    # A set on the right of \from is no set of written locations; \result and \nothing write nothing.
    assert at("pure") == {"status": "listed", "terms": []}
    assert at("both") == {"status": "listed", "terms": ["*p", "errno"]}


def _plat_model(tree: Path) -> dict:
    (tree / "plat.h").write_text(_PLAT_HEADER, encoding="utf-8", newline="\n")
    lines = _PLAT_HEADER.splitlines()

    def decl(name: str) -> dict:
        line = next(i for i, text in enumerate(lines, 1) if f" {name}(" in text)
        return {"decl": f"/framac-scratch/tree/plat.h:{line}", "proto": f"void {name}();"}

    names = ("fill", "two", "pair", "bare", "pure", "both")
    functions = {
        "a.c#login": fn("login", writes={"pointer": 0, "params": [], "globals": ["auth_ok"]}),
        "a.c#admin": fn("admin"),
        "a.c#uses_fill": fn("uses_fill", external_calls=["fill", "pure"]),
        "a.c#uses_two": fn("uses_two", external_calls=["two"]),
        "a.c#uses_pair": fn("uses_pair", external_calls=["pair", "fill"]),
        "a.c#uses_bare": fn("uses_bare", external_calls=["bare", "lost"]),
        "a.c#uses_pure": fn("uses_pure", external_calls=["pure"]),
    }
    return model(
        functions,
        tree="/framac-scratch/tree",
        external_decls={n: decl(n) for n in names},
        external_formals={"fill": [{"name": "out", "kind": "pointer"}]},
        global_variables={"auth_ok": {"name": "auth_ok", "file": "a.c", "type": "int"}},
    )


@pytest.mark.unit
def test_a_set_valued_assigns_takes_its_callers_out_of_a_writing_property(tmp_path):
    """
    R's constraint: a declared callee whose `assigns` holds a set stops MetAcsl (meta_annotate.ml line
    675). Its callers leave the property's targets and are reported, per property; a callee without
    `assigns`, for which MetAcsl generates nothing, is listed too.
    """
    m = _plat_model(tmp_path)
    lists = {
        "auth_gates": [{"function": "login", "state": "auth_ok", "protects": ["admin"], "description": "d"}],
        "assets": [{"name": "auth", "lvalue": "auth_ok", "writers": ["login"], "description": "d"}],
        "invariants": [_inv("monotonic", name="auth_up", lvalue="auth_ok")],
    }
    doc = sp.generate(m, threat(**lists), roots=[tmp_path])
    assert not sp.validate(doc), sp.validate(doc)
    props = by_name(doc)
    for name in ("L4_auth_state_login", "L3_writers_auth", "L4_invariant_auth_up"):
        prop = props[name]
        but = "uses_pair, uses_two" if name == "L4_invariant_auth_up" else "login, uses_pair, uses_two"
        assert f"\\targets(\\diff(\\ALL, {{{but}}}))" in prop["acsl"], prop["acsl"]
        # The caller of a callee that assigns something is an instance; one of a pure callee is not.
        assert "a.c#uses_fill" in prop["instances"] and "a.c#uses_pure" not in prop["instances"]
        assert not {"a.c#uses_two", "a.c#uses_pair"} & set(prop["instances"])
        assert [(u["function"], u["callee"]) for u in prop["unchecked"]] == [
            ("a.c#uses_pair", "pair"),
            ("a.c#uses_two", "two"),
        ]
        declared = prop["declared_callees"]
        assert [(c["callee"], c["callers"]) for c in declared["set_assigns"]] == [
            ("pair", ["a.c#uses_pair"]),
            ("two", ["a.c#uses_two"]),
        ]
        assert declared["set_assigns"][1]["decl"] == "/framac-scratch/tree/plat.h:6"
        assert [(c["callee"], c["callers"]) for c in declared["no_assigns"]] == [("bare", ["a.c#uses_bare"])]
        # `lost` has no declaration in the model: its contract is unknown, and said so.
        assert [c["callee"] for c in declared["unknown"]] == ["lost"]
        assert [w for w in doc["warnings"] if f"({name}): pair, two assign(s) a set" in w]
        assert [w for w in doc["warnings"] if f"({name}): the declared function(s) bare have no `assigns`" in w]
    # Every warning of the new kinds starts with its item's kind (generate_report.py selects on it).
    mine = [w for w in doc["warnings"] if not w.startswith("the model ")]
    assert len(mine) == 6 and all(w.startswith(("auth gate ", "asset ", "invariant ")) for w in mine), mine
    # The callers left out keep an obligation that says so: their unit must not be credited from a
    # run that has no goal for it.
    marked = [o for o in doc["obligations"]["a.c#uses_two"] if o.get("unchecked")]
    assert {o["property"] for o in marked} == {"L4_auth_state_login", "L3_writers_auth", "L4_invariant_auth_up"}
    # Without the declarations nothing is known, and nothing is invented: every contract is `unknown`.
    blind = by_name(sp.generate(m, threat(**lists)))["L4_auth_state_login"]
    assert list(blind["declared_callees"]) == ["unknown"] and "unchecked" not in blind
    assert "\\targets(\\diff(\\ALL, {login}))" in blind["acsl"] and blind["instances"] == []


# ---------------------------------------------------------------------------------------------------
# Acceptance (Docker): the new kinds and the initializer checks against the real MetAcsl and WP
# ---------------------------------------------------------------------------------------------------


def _wp_rows(run: Path, name: str) -> tuple[list[dict], list[dict]]:
    """
    (proven, unproven) rows of the WP report CSVs under run/workspace/wp that belong to property `name`.
    run_wp_function.py lists proven goals only for the classes it knows (layer_goals), which the
    classes of package D1 are not yet (package D2), so the rows are read from the CSV: a generated
    `requires`, `ensures` or in-code `check` carries the name, a generated assertion is located at its
    property's line in the meta file.
    """
    wp = run / "workspace" / "wp"
    lines: dict[str, dict[int, str]] = {
        p.name: sp.meta_line_names(p.read_text(encoding="utf-8")) for p in wp.glob("security_meta_*.c")
    }
    proven, unproven = [], []
    for csv_path in sorted(wp.glob("*.csv")):
        for row in rwf.read_report_csv(csv_path):
            named = lines.get(Path(str(row["file"])).name, {}).get(row["line"]) == name
            if not named and f"{name}:" not in str(row["property"]) and f"'{name}," not in str(row["property"]):
                continue
            (proven if row["status"] == rwf.STATUS_VALID else unproven).append(row)
    return proven, unproven


@pytest.mark.unit
def test_every_kind_variant_has_a_program_and_its_property(tmp_path):
    assert set(KIND_VARIANTS) == set(KIND_VARIANT_OF) and not set(KIND_VARIANTS) & set(TEMPLATE_VARIANTS)
    for variant, (_, name, lists) in KIND_VARIANTS.items():
        target = _one_file_target(tmp_path / variant, VARIANTS_DIR / f"{variant}.c", lists, False)
        assert trust.load_threat_model(target / "THREAT_MODEL.md")["status"] == "ok", variant
        assert any(name.startswith(prefix) for prefix in sp.NAME_PREFIX.values()), name
    # Every variant section of the three templates is exercised by a program.
    assert {"global", "formal", "entry"} | set(sp.load_template("l4_invariant")) - {"init_strong"} == set(
        KIND_VARIANT_OF.values()
    )


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    ("variant", "violate"),
    [
        pytest.param(v, bad, id=f"{v}-{'violated' if bad else 'satisfied'}")
        for v in sorted(KIND_VARIANTS)
        for bad in (False, True)
    ],
)
def test_kind_variant_acceptance_in_the_image(model_run, tmp_path, variant, violate):  # noqa: F811
    """
    Step 0 and acceptance of package D1: each new template variant, generated from a threat model,
    against the real model, MetAcsl and WP. On the program that satisfies the property its goals
    prove; on the one that violates it a goal named after the property stays unproven: MetAcsl
    accepts the template and does not instantiate it as trivially true.
    """
    function, name, lists = KIND_VARIANTS[variant]
    target = _one_file_target(tmp_path / "target", VARIANTS_DIR / f"{variant}.c", lists, violate)
    run = tmp_path / "run"
    m = model_run(target, run, "make")
    assert m["status"] == "ok"
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"), roots=[target])
    assert not sp.validate(doc), sp.validate(doc)
    props = by_name(doc)
    assert name in props, doc["warnings"]
    assert props[name]["variant"] == KIND_VARIANT_OF[variant], props[name]
    assert f"prog.c#{function}" in props[name]["instances"], props[name]
    write_json(run / "workspace/reports/security_props.json", doc)
    report = _forward_wp(target, run, function, " -DVIOLATE" if violate else "")
    assert name in report["security_props"]["properties"], report.get("security_props")
    assert not report["security_props"].get("error"), report["security_props"]
    proven, unproven = _wp_rows(run, name)
    detail = json.dumps({"proven": proven, "unproven": unproven, "log": report.get("wp_log_tail")}, indent=1)
    if violate:
        assert unproven and report["status"] != "all_proven", detail
    else:
        assert proven and not unproven and report["status"] == "all_proven", detail


def _init_meta_annotations(defs: str) -> dict[str, list[str]]:
    """function -> the names of the annotations MetAcsl generates in it for local_init_meta.c."""
    script = (
        (
            f"frama-c -cpp-extra-args='{defs}' /fx/local_init.c /fx/local_init_meta.c -meta -meta-warn-key "
            "unknown-func=inactive -then-last -print -ocode /tmp/out.c >/tmp/log 2>&1 || {{ cat /tmp/log; exit 1; }}; "
            "cat /tmp/out.c"
        )
        .replace("{{", "{")
        .replace("}}", "}")
    )
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{INIT_DIR.resolve()}:/fx:ro", ANALYSIS_IMAGE, "-c", f"timeout 300 sh -c \"{script}\"",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    out: dict[str, list[str]] = {}
    current = None
    for line in res.stdout.splitlines():
        m = re.match(r"(?:static )?(?:void|int) (\w+)\(", line)
        if m:
            current = m.group(1)
        found = re.search(r"assert (L\d_\w+): meta:", line)
        if found and current:
            out.setdefault(current, []).append(found.group(1))
    return out


@pytest.mark.integration
@pytest.mark.slow
def test_metacsl_skips_calls_in_initializers_in_the_image():
    """
    Step 0 of package E, kept as a watch on MetAcsl itself (the hand-written local_init_meta.c, not
    the generator): a statement call gets its \\calling, \\writing and \\strong_invariant instances, the
    same call placed in an initializer gets none, and \\reading handles both. When this fails, MetAcsl
    changed: the in-code checks of package E may no longer be needed.
    """
    require_docker_images(ANALYSIS_IMAGE)
    found = _init_meta_annotations("-DVIOLATE")
    assert found["f_assign"] == ["L4_invariant_auth_range", "L5_sanitized_net_send", "L4_invariant_auth_range"]
    assert found["g_assign"] == ["L5_sanitized_net_send", "L6_no_leak_key", "L4_invariant_auth_range"]
    assert found["h_assign"] == ["L4_auth_state_login", "L4_invariant_auth_range"]
    # f_init keeps the assertion after its statement call of prepare(), and nothing at its initializer.
    assert found.get("f_init") == ["L4_invariant_auth_range"]
    assert "g_init" not in found and "h_init" not in found
    assert found["r_assign"] == found["r_init"] == ["L6_no_leak_read_key"]


def _model_with_initializer_flags(scripts: Path, target: Path, run: Path) -> dict:
    """
    The build capture and the model of `target`, as the model_run fixture runs them, with `scripts`
    mounted as the pipeline's scripts (a copy holding the pass-through phase0_model.py still lacks).
    """
    run.mkdir(parents=True, exist_ok=True)
    vol = f"p0model-d1-{uuid.uuid4().hex[:12]}"
    try:
        subprocess.run(["docker", "volume", "create", vol], capture_output=True, check=True, timeout=120)
        common = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{target.resolve()}:/target:ro", "-v", f"{run.resolve()}:/framac-run",
            "-v", f"{vol}:/framac-scratch",
            "-v", f"{scripts.resolve()}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro", "-w", "/framac-run",
        ]  # fmt: skip
        py = "python3 /opt/framac-pipeline/scripts"
        for image, entry, command in (
            (BUILD_IMAGE, [], f"{py}/build_capture.py run --scratch /framac-scratch --recipe-file '' --command 'make'"),
            (ANALYSIS_IMAGE, ["--entrypoint", "sh"], f"{py}/phase0_model.py run"),
        ):
            args = [*common, *entry, image, *(["-c", command] if entry else [command])]
            res = subprocess.run(
                args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
            )
            assert res.returncode == 0, res.stdout + res.stderr
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True, check=False, timeout=120)
    return json.loads((run / "workspace/reports/phase0_model.json").read_text(encoding="utf-8"))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("violate", [False, True], ids=["satisfied", "violated"])
def test_initializer_checks_acceptance_in_the_image(tmp_path, violate):
    """
    Acceptance of package E, D1 half: phase0_dump.ml marks the calls placed in initializers, the
    generator writes a check named after each property MetAcsl skips there, and WP has it as a goal:
    f_init, g_init and h_init each carry one, proved on the correct program and unproven on the
    violating one. The model keeps the dump's flag only through the pass-through this test applies
    to a copy of scripts/phase0_model.py (PASSTHROUGH_TO): the file is not package D1's.
    """
    require_docker_images(ANALYSIS_IMAGE, BUILD_IMAGE)
    scripts = tmp_path / "scripts"
    shutil.copytree(ROOT / "scripts", scripts, ignore=shutil.ignore_patterns("__pycache__"))
    text = (scripts / "phase0_model.py").read_text(encoding="utf-8")
    if PASSTHROUGH_TO not in text:
        assert text.count(PASSTHROUGH_FROM) == 1, "phase0_model._call_sites changed: update the stand-in"
        text = text.replace(PASSTHROUGH_FROM, PASSTHROUGH_TO)
        (scripts / "phase0_model.py").write_text(text, encoding="utf-8", newline="\n")
    lists = {**INIT_LISTS, "auth_gates": [INIT_GATE], "invariants": [INIT_STRONG]}
    target = _one_file_target(tmp_path / "target", INIT_DIR / "local_init.c", lists, violate)
    run = tmp_path / "run"
    m = _model_with_initializer_flags(scripts, target, run)
    assert m["status"] == "ok"
    # The flag comes from this tree's phase0_dump.ml: a statement call says false, an initializer true.
    flags = {
        name: [s["initializer"] for s in m["functions"][f"prog.c#{name}"]["call_sites"] if s["callee"] != "prepare"]
        for name in ("f_assign", "f_init", "g_assign", "g_init", "h_assign", "h_init")
    }
    assert flags == {n: [n.endswith("_init")] for n in flags}, flags
    # The work tree: a copy of the target, where the checks are written.
    work = tmp_path / "work"
    shutil.copytree(target, work)
    doc = sp.generate(m, trust.load_threat_model(target / "THREAT_MODEL.md"), roots=[work])
    assert not [w for w in doc["warnings"] if "initializers" in w], doc["warnings"]
    applied = sp.apply_taint(doc, work, taint=False)
    assert not applied["init_unplaced"] and not applied["skipped"], applied
    doc["code_checks"] = applied["code_checks"]
    assert not sp.validate(doc), sp.validate(doc)
    write_json(run / "workspace/reports/security_props.json", doc)
    expected = {
        "f_init": ["L5_sanitized_net_send", "L6_no_leak_key"],
        "g_init": ["L5_sanitized_net_send", "L6_no_leak_key"],
        "h_init": ["L4_auth_state_login", "L4_invariant_auth_range"],
    }
    assert {
        f: sorted(c["property"] for c in applied["code_checks"] if c["function"] == f"prog.c#{f}") for f in expected
    } == expected
    # Which of them the -DVIOLATE program breaks: uninitialized bytes sent (f), the key sent (g), the
    # auth state written by a declared callee, and with it the invariant no longer known to hold (h).
    broken = {
        "f_init": {"L5_sanitized_net_send"},
        "g_init": {"L6_no_leak_key"},
        "h_init": {"L4_auth_state_login", "L4_invariant_auth_range"},
    }
    for function, names in expected.items():
        report = _forward_wp(work, run, function, " -DVIOLATE" if violate else "")
        assert not (report.get("security_props") or {}).get("error"), report.get("security_props")
        # Frama-C's report gives a check its file and line, not its name: the checks of one line are
        # told apart by their order there (`index` of the code check).
        rows = [
            r
            # The first pass: a retry (`_retry`, `_bytes`, ...) writes the same rows to a CSV of its own.
            for r in rwf.read_report_csv(run / "workspace" / "wp" / f"wp_{function}.csv")
            if r["file"] == "prog.c" and r["function"] == function and r["kind"] == "user check"
        ]
        placed = [c for c in applied["code_checks"] if c["function"] == f"prog.c#{function}"]
        detail = json.dumps({"rows": rows, "placed": placed, "log": report.get("wp_log_tail")}, indent=1)
        assert len(rows) == len(placed) == len(names), detail
        for check in placed:
            row = [r for r in rows if r["line"] == check["line"]][check["index"]]
            if violate and check["property"] in broken[function]:
                assert row["status"] != rwf.STATUS_VALID, f"{function} {check['property']}\n{detail}"
            else:
                assert row["status"] == rwf.STATUS_VALID, f"{function} {check['property']}\n{detail}"
        if not violate:
            assert report["status"] == "all_proven", detail
        for csv_path in (run / "workspace" / "wp").glob("*.csv"):
            csv_path.unlink()
