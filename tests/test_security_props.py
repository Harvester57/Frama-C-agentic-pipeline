"""
Security layers via MetAcsl (docs/phase0-implementation-plan.md step I9): property generation from the
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
from pathlib import Path

import pytest

import ledger as L
import run_wp_function as rwf
import security_props as sp
import trust
from acsl_ast import tokenize_c_acsl
from conftest import ANALYSIS_IMAGE, write_json
from test_phase0_model import model_run  # noqa: F401  (Docker fixture)

ROOT = Path(__file__).resolve().parent.parent
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
    m = re.search(r"predicate\s+" + name + r"\s*\([^)]*\)\s*=[\s\S]*?;[ \t]*\n", text + "\n")
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
    assert text.startswith(sp.META_INCLUDE + "\n" + doc["preamble"])
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
# Open pipeline bugs (docs/troubleshooting.md): (variant, violate) -> reason.
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
    assert sorted(p.stem for p in VARIANTS_DIR.glob("*.c")) == sorted(TEMPLATE_VARIANTS)
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
    proved = re.search(r"Proved goals:\s+(\d+) / (\d+)", res.stdout)
    assert proved and int(proved.group(2)) >= 2, res.stdout
    assert (proved.group(1) == proved.group(2)) is (not violate), res.stdout


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
    proved = re.search(r"Proved goals:\s+(\d+) / (\d+)", res.stdout)
    assert proved and int(proved.group(2)) >= 2, res.stdout
    assert (proved.group(1) == proved.group(2)) is (not violate), res.stdout
