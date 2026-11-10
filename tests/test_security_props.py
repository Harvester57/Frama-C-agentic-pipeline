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
    # The log sink is external: its writers (callers) discharge the check.
    assert props["L5_sanitized_log_line"]["instances"] == ["session.c#session_admin", "session.c#session_status"]
    assert "L5_no_crlf(\\called_arg(msg))" in props["L5_sanitized_log_line"]["acsl"]
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
    assert text.startswith(doc["preamble"])
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
# Open pipeline bugs (docs/troubleshooting.md): (variant, violate) -> reason.
OPEN_DEFECTS = {
    ("l6_no_leak_calling_static", False): (
        "MetAcsl's default -meta-simpl drops an instance it decides statically (a global separated from the "
        "secret), so the satisfied program has no L6_no_leak goal and ledger.py ingest-wp never credits the unit"
    ),
}


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


def _variant_target(dest: Path, variant: str, violate: bool) -> Path:
    """A one-file target: variants/<variant>.c as prog.c, its Makefile and THREAT_MODEL.md."""
    dest.mkdir(parents=True)
    shutil.copy(VARIANTS_DIR / f"{variant}.c", dest / "prog.c")
    defs = "-DVIOLATE" if violate else ""
    (dest / "Makefile").write_text(_VARIANT_MAKEFILE.format(defs=defs), encoding="utf-8", newline="\n")
    block: dict = {"schema_version": 1, "target": variant, "input_sources": [], "trusted_callers": []}
    block.update({"secrets": [], "auth_gates": [], "output_sinks": []})
    block.update(TEMPLATE_VARIANTS[variant][2])
    text = f"# Threat model: {variant}\n\n```json framac-threat-model\n{json.dumps(block, indent=1)}\n```\n"
    (dest / "THREAT_MODEL.md").write_text(text, encoding="utf-8", newline="\n")
    return dest


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
def test_template_variant_acceptance_in_the_image(model_run, tmp_path, variant, violate):  # noqa: F811
    """
    The named goal of each template variant proves on a program that satisfies the property and stays
    unproven on one that violates it: MetAcsl accepts the template and it is not trivially true.
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
    else:
        assert proven and not unproven, detail
