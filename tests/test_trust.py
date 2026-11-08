"""
Trust boundary (plan step I7): scripts/trust.py's rules, the structured threat model, the optional
CodeQL facts (adds untrusted marks only) and the consumers (harness reachability, the contract
trust-boundary check, the report). The Docker-backed test runs capture + model on every Phase 0
fixture and compares each function's trust with the fixture's `trust` truth.
"""

import copy
import json
import sys
from pathlib import Path

import pytest

import trust as T
from conftest import PHASE0_FIXTURES
from test_phase0_model import model_run  # noqa: F401  (the Docker capture + model fixture)

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.unit


def _fn(name, file, *, units, calls_ext=(), static=False, signature="int(int)"):
    return {
        "name": name,
        "file": file,
        "static": static,
        "signature": signature,
        "units": list(units),
        "external_calls": sorted(calls_ext),
    }


def _model():
    """libp.a (API p_parse, p_len; internal p_step, p_hidden) and tool (main(argc, argv) -> p_parse, t_read)."""
    fns = {
        "src/p.c#p_parse": _fn("p_parse", "src/p.c", units=["libp.a"]),
        "src/p.c#p_len": _fn("p_len", "src/p.c", units=["libp.a"]),
        "src/p.c#p_step": _fn("p_step", "src/p.c", units=["libp.a"], static=True),
        "src/p.c#p_hidden": _fn("p_hidden", "src/p.c", units=["libp.a"]),
        "tools/t.c#main": _fn("main", "tools/t.c", units=["tool"], signature="int(int,char **)"),
        "tools/t.c#t_read": _fn("t_read", "tools/t.c", units=["tool"], calls_ext=["fread"]),
        "tools/t.c#t_fmt": _fn("t_fmt", "tools/t.c", units=["tool"]),
        "tests/u.c#test_main": _fn("test_main", "tests/u.c", units=["unit_test"]),
    }
    return {
        "status": "ok",
        "functions": fns,
        "units": {
            "libp.a": {"kind": "static_lib", "test": False, "entry_points": ["src/p.c#p_parse", "src/p.c#p_len"]},
            "tool": {"kind": "executable", "test": False, "entry_points": ["tools/t.c#main"]},
            "unit_test": {"kind": "executable", "test": True, "entry_points": []},
        },
        "edges": [
            {"caller": "src/p.c#p_parse", "callee": "src/p.c#p_step", "kind": "direct"},
            {"caller": "tools/t.c#main", "callee": "tools/t.c#t_read", "kind": "direct"},
            {"caller": "tools/t.c#t_read", "callee": "src/p.c#p_parse", "kind": "direct"},
            {"caller": "tests/u.c#test_main", "callee": "src/p.c#p_hidden", "kind": "direct"},
        ],
        "externals": ["fread", "printf"],
        "macro_aliases": {},
    }


def _threat(block):
    return {"status": T.STATUS_OK, "block": block}


def _block(**kw):
    base = {"schema_version": 1, "input_sources": [], "secrets": [], "auth_gates": [], "output_sinks": []}
    base.update(kw)
    return base


def _md(block) -> str:
    return "# Threat model\n\nProse.\n\n```framac-threat-model\n" + json.dumps(block, indent=1) + "\n```\n"


# ---------------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------------


def test_rules_without_a_threat_model():
    r = T.compute_trust(_model())
    f = r["functions"]
    assert f["src/p.c#p_parse"]["value"] == "untrusted" and f["src/p.c#p_parse"]["source"] == "default"
    assert f["src/p.c#p_parse"]["sources"] == ["default", "call_graph"] and f["src/p.c#p_parse"]["boundary"]
    assert f["src/p.c#p_len"]["sources"] == ["default"] and f["src/p.c#p_len"]["boundary"]
    # Reached from main(argc, argv) through the reader: untrusted, not a boundary.
    assert f["src/p.c#p_step"]["source"] == "call_graph" and not f["src/p.c#p_step"]["boundary"]
    assert f["tools/t.c#main"]["source"] == "call_graph" and f["tools/t.c#main"]["boundary"]
    assert f["tools/t.c#t_read"]["value"] == "untrusted"
    # Called only from a test unit, and not on any input path: trusted.
    assert f["src/p.c#p_hidden"] == {**f["src/p.c#p_hidden"], "value": "trusted", "source": "default"}
    assert f["tools/t.c#t_fmt"]["value"] == "trusted"
    assert r["summary"]["untrusted"] == 5 and r["summary"]["boundary"] == 3
    assert r["codeql"] == {"status": "off"} and "unit_test" not in r["units"]


def test_main_without_argv_is_a_root_only_through_a_reader():
    m = _model()
    m["functions"]["tools/t.c#main"]["signature"] = "int(void)"
    f = T.compute_trust(m)["functions"]
    assert f["tools/t.c#main"]["value"] == "trusted"  # no argv, no reader of its own
    assert f["tools/t.c#t_read"]["source"] == "call_graph" and not f["tools/t.c#t_read"]["boundary"]
    m["functions"]["tools/t.c#main"]["external_calls"] = ["getenv"]
    f = T.compute_trust(m)["functions"]
    assert f["tools/t.c#main"]["value"] == "untrusted" and not f["tools/t.c#main"]["boundary"]


def test_models_without_external_calls_warn():
    m = _model()
    for f in m["functions"].values():
        f.pop("external_calls")
    assert any("external calls" in w for w in T.compute_trust(m)["warnings"])


@pytest.mark.parametrize(
    "sig,expected",
    [("int(int,char **)", True), ("int(void)", False), ("int()", False), ("", True), (None, True), ("x", True)],
)
def test_has_parameters(sig, expected):
    assert T.has_parameters(sig) is expected


def test_threat_model_entry_reader_and_trusted_callers():
    block = _block(
        input_sources=[
            {"function": "p_hidden", "role": "entry"},
            {"function": "tools/t.c#t_fmt", "role": "reader"},
            {"function": "recv", "role": "reader"},
            {"function": "nowhere", "role": "entry"},
        ],
        trusted_callers=[{"functions": ["p_len"], "reason": "only the tool calls it, after checks"}],
    )
    r = T.compute_trust(_model(), _threat(block))
    f = r["functions"]
    assert f["src/p.c#p_hidden"]["source"] == "threat_model" and f["src/p.c#p_hidden"]["boundary"]
    assert f["tools/t.c#t_fmt"]["source"] == "threat_model" and not f["tools/t.c#t_fmt"]["boundary"]
    assert f["src/p.c#p_len"]["value"] == "trusted" and f["src/p.c#p_len"]["source"] == "threat_model"
    assert f["src/p.c#p_len"]["overridden"] == ["default"] and r["summary"]["overridden"] == 1
    assert any("nowhere" in w for w in r["warnings"])
    assert any("reader recv" in w for w in r["warnings"])  # neither defined nor called in this build
    assert not any("p_hidden" in w for w in r["warnings"])
    # A unit as trusted callers, with an exception.
    block = _block(trusted_callers=[{"unit": "libp.a", "except": ["p_parse"], "reason": "internal library"}])
    f = T.compute_trust(_model(), _threat(block))["functions"]
    assert f["src/p.c#p_len"]["value"] == "trusted" and f["src/p.c#p_parse"]["value"] == "untrusted"


def test_codeql_only_adds_untrusted_marks():
    base = T.compute_trust(_model())
    facts = {
        "status": "ok",
        "facts": [
            {"function": "tools/t.c#t_fmt", "kind": "parameter", "parameter": "s",
             "source": {"type": "remote", "file": "tools/t.c", "line": 3}},
            {"function": "src/p.c#p_parse", "kind": "source_site", "parameter": None, "source": {"type": "local"}},
            {"function": "gone.c#ghost", "kind": "parameter", "parameter": "x", "source": {}},
        ],
    }  # fmt: skip
    trusted_by_tm = _threat(_block(trusted_callers=[{"functions": ["p_len", "t_fmt"], "reason": "checked"}]))
    for threat in (None, trusted_by_tm):
        before = T.compute_trust(_model(), threat)
        after = T.compute_trust(_model(), threat, facts)
        for fid, rec in before["functions"].items():
            if rec["value"] == "untrusted":
                assert after["functions"][fid]["value"] == "untrusted", fid
            assert set(rec["sources"]) <= set(after["functions"][fid]["sources"]), fid
            if rec["source"] == "threat_model":
                assert after["functions"][fid]["value"] == rec["value"], fid  # CodeQL never overrides it
    after = T.compute_trust(_model(), None, facts)
    assert after["functions"]["tools/t.c#t_fmt"]["source"] == "codeql"
    assert after["functions"]["src/p.c#p_parse"]["sources"] == ["default", "call_graph", "codeql"]
    assert after["codeql"]["facts"] == 2 and after["codeql"]["unmatched"] == 1
    assert after["summary"]["with_codeql"] == 2
    assert base["functions"]["tools/t.c#t_fmt"]["value"] == "trusted"
    failed = T.compute_trust(_model(), None, {"status": "database_failed", "facts": facts["facts"]})
    assert failed["functions"] == base["functions"]


# ---------------------------------------------------------------------------------------------------
# Threat model
# ---------------------------------------------------------------------------------------------------


def test_threat_model_block_parsing_and_validation(tmp_path):
    good = _block(
        target="demo",
        input_sources=[{"function": "src/p.c#p_parse", "role": "entry", "params": ["buf", "len"], "description": "d"}],
        trusted_callers=[{"unit": "libp.a", "except": ["p_parse"], "reason": "x"}],
        secrets=[{"name": "key", "kind": "global", "description": "d"}],
        auth_gates=[{"function": "p_len", "state": "authenticated", "protects": ["p_parse"], "description": "d"}],
        output_sinks=[{"function": "printf", "kind": "terminal", "description": "d"}],
    )
    path = tmp_path / "THREAT_MODEL.md"
    path.write_bytes(_md(good).encode())
    tm = T.load_threat_model(path)
    assert tm["status"] == "ok" and tm["block"] == good and len(tm["sha256"]) == 64
    assert T.load_threat_model(tmp_path / "missing.md")["status"] == "no_threat_model"
    path.write_bytes(b"# Threat model\n\nOnly prose.\n")
    assert T.load_threat_model(path)["status"] == "no_threat_model"
    bad = [
        {**good, "input_sources": [{"function": "p", "role": "sink"}]},
        {**good, "extra": 1},
        {k: v for k, v in good.items() if k != "secrets"},
        {**good, "trusted_callers": [{"unit": "libp.a", "functions": ["p"], "reason": "x"}]},
        {**good, "trusted_callers": [{"functions": ["p"], "except": ["q"], "reason": "x"}]},
    ]
    for block in bad:
        path.write_bytes(_md(block).encode())
        tm = T.load_threat_model(path)
        assert tm["status"] == "invalid_threat_model" and tm["errors"], block
    path.write_bytes(b"```framac-threat-model\n{not json\n```\n")
    assert T.load_threat_model(path)["status"] == "invalid_threat_model"
    path.write_bytes((_md(good) + _md(good)).encode())
    assert "exactly one" in T.load_threat_model(path)["errors"][0]
    path.write_bytes(_md(good).replace("```framac-threat-model", "```json framac-threat-model").encode())
    assert T.load_threat_model(path)["status"] == "ok"


def test_find_threat_model_order(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "THREAT_MODEL.md").write_bytes(b"x")
    assert T.find_threat_model(None, {"tree": str(tree)}) == tree / "THREAT_MODEL.md"
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "THREAT_MODEL.md").write_bytes(b"x")
    assert T.find_threat_model(None, {"tree": str(tree)}) == Path("workspace/THREAT_MODEL.md")
    assert T.find_threat_model(Path("explicit.md"), None) == Path("explicit.md")


@pytest.mark.parametrize("asset", ["minmea", "qcbor", "x509-parser"])
def test_benchmark_threat_models_validate(asset):
    path = ROOT / "benchmark" / "assets" / asset / "THREAT_MODEL.md"
    tm = T.load_threat_model(path)
    assert tm["status"] == "ok", tm["errors"]
    manifest = json.loads((ROOT / "benchmark" / "manifest.json").read_text(encoding="utf-8"))
    entries = [
        t["threat_model"]
        for t in manifest["targets"]
        if (t.get("threat_model") or {}).get("path", "").startswith(f"{asset}/")
    ]
    assert entries and all(e["sha256"] == tm["sha256"] for e in entries)


def test_check_threat_model_cli(tmp_path, capsys):
    path = tmp_path / "THREAT_MODEL.md"
    path.write_bytes(_md(_block()).encode())
    assert T.main(["check-threat-model", str(path), "--model", str(tmp_path / "none.json")]) == 0
    path.write_bytes(_md({"schema_version": 1}).encode())
    assert T.main(["check-threat-model", str(path), "--model", str(tmp_path / "none.json")]) == 2
    assert T.main(["check-threat-model", str(tmp_path / "absent.md")]) == 1
    capsys.readouterr()


# ---------------------------------------------------------------------------------------------------
# Annotation and consumers
# ---------------------------------------------------------------------------------------------------


def test_annotate_model_validates_and_codeql_needs_the_run_opt_in(tmp_path, monkeypatch):
    import phase0_model as pm

    monkeypatch.chdir(tmp_path)
    model = _model()
    for fid, f in model["functions"].items():
        f.update(id=fid)
    plain = copy.deepcopy(model)
    block = T.annotate_model(plain, tmp_path / "none.md")
    assert block["threat_model"]["status"] == "no_threat_model" and block["codeql"] == {"status": "off"}
    assert all(u["trust"]["threat_model"] == "no_threat_model" for u in plain["units"].values())
    assert plain["units"]["unit_test"]["trust"]["functions"] == 0
    facts = tmp_path / "codeql_trust.json"
    facts.write_text(json.dumps({"status": "ok", "facts": [
        {"function": "tools/t.c#t_fmt", "kind": "source_site", "parameter": None, "source": {"type": "remote"}}]}))  # fmt: skip
    off = copy.deepcopy(model)
    assert (
        T.annotate_model(off, None, facts, {"codeql": {"enabled": True, "open_source": False}})["codeql"]["status"]
        == "off"
    )
    assert {k: v["trust"] for k, v in off["functions"].items()} == {
        k: v["trust"] for k, v in plain["functions"].items()
    }
    on = copy.deepcopy(model)
    blk = T.annotate_model(on, None, facts, {"codeql": {"enabled": True, "open_source": True}})
    assert blk["codeql"]["facts"] == 1 and on["functions"]["tools/t.c#t_fmt"]["trust"]["source"] == "codeql"
    missing = copy.deepcopy(model)
    meta = {"codeql": {"enabled": True, "open_source": True}}
    assert T.annotate_model(missing, None, tmp_path / "nope.json", meta)["codeql"]["status"] == "not_run"
    # The trust blocks satisfy the model schema's definitions.
    from minischema import Validator, load_schema

    schema = load_schema(ROOT / "schemas" / "phase0_model.schema.json")
    defs = schema.get("definitions") or schema.get("$defs") or {}
    for rec in on["functions"].values():
        assert not list(Validator({**defs["function_trust"], "definitions": defs}).errors(rec["trust"]))
    assert hasattr(pm, "annotate_trust")


def test_function_trust_merges_same_named_records_and_reachability():
    records = {
        "a.c#f": {"name": "f", "file": "a.c", "trust": {"value": "trusted", "source": "default", "boundary": False}},
        "b.c#f": {"name": "f", "file": "b.c", "trust": {"value": "untrusted", "source": "call_graph", "boundary": False}},
        "g": {"name": "g", "file": "a.c", "trust": {"value": "untrusted", "source": "default", "boundary": True}},
    }  # fmt: skip
    assert (T.function_trust(records, "f") or {})["value"] == "untrusted"
    assert (T.function_trust(records, "f", "a.c") or {})["value"] == "trusted"
    assert (T.function_trust(records, "a.c#f") or {})["source"] == "default"
    assert T.function_trust(records, "nope") is None
    assert T.reachability_of(T.function_trust(records, "g")) == "untrusted_surface"
    assert T.reachability_of(T.function_trust(records, "f")) == "internal_api"
    assert T.reachability_of(None) is None


def _dag(tmp_path, functions):
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    (reports / "callgraph_dag.json").write_text(json.dumps({"functions": functions}), encoding="utf-8")
    return tmp_path / "workspace"


def test_harness_reachability_defaults_from_trust(tmp_path, monkeypatch):
    import generate_harness as gh

    monkeypatch.chdir(tmp_path)
    ws = _dag(tmp_path, {
        "api": {"name": "api", "trust": {"value": "untrusted", "source": "default", "boundary": True}},
        "inner": {"name": "inner", "trust": {"value": "untrusted", "source": "call_graph", "boundary": False}},
    })  # fmt: skip
    out_dir = ws / "harnesses"
    assert gh._trust_reachability(out_dir, "api") == ("untrusted_surface", "trust:default")
    assert gh._trust_reachability(out_dir, "inner") == ("internal_api", "trust:call_graph")
    assert gh._trust_reachability(out_dir, "absent") is None
    assert gh._trust_reachability(tmp_path / "elsewhere" / "h", "api") == ("untrusted_surface", "trust:default")


def test_acsl_trust_boundary_and_overlay_synthetic_entry(tmp_path):
    import acsl_ast
    import workspace_overlay as wo

    ws = _dag(tmp_path, {
        "api": {"name": "api", "trust": {"value": "untrusted", "source": "default", "boundary": True}},
        "inner": {"name": "inner", "trust": {"value": "untrusted", "source": "call_graph", "boundary": False}},
    })  # fmt: skip
    records = acsl_ast.function_trust_records(ws)
    assert acsl_ast.is_trust_boundary(records, "api") is True
    assert acsl_ast.is_trust_boundary(records, "inner") is False
    assert acsl_ast.is_trust_boundary(records, "absent") is None
    assert acsl_ast.function_trust_records(tmp_path / "nowhere") == {}
    metas = wo._untrusted_entry_metas(ws, None, "api")
    assert metas == [{"entry_fn": "api", "reachability": "untrusted_surface", "trust_boundary": True}]
    assert wo._untrusted_entry_metas(ws, None, "inner") == []


def test_report_trust_lines():
    import generate_report as gr

    model = _model()
    model["trust"] = T.annotate_model(model, Path("/nonexistent/THREAT_MODEL.md"))
    lines = gr.trust_lines(model)
    text = "\n".join(lines)
    assert lines[0] == "### Trust boundary" and "`no_threat_model`" in text and "**CodeQL:** `off`" in text
    assert "| `libp.a` | `src/p.c#p_parse` | untrusted (boundary) | default (also call_graph) |" in text
    assert "`tools/t.c#main`" in text and "unit_test" not in text
    assert gr.trust_lines(None) == [] and gr.trust_lines({"functions": {}}) == []


def test_run_metadata_set_codeql(tmp_path, monkeypatch):
    import run_metadata

    run = tmp_path / "run-77"
    run.mkdir()
    monkeypatch.chdir(run)
    monkeypatch.setattr(run_metadata, "toolchain", lambda: {})
    monkeypatch.setattr(run_metadata, "resources_summary", lambda: None)
    run_metadata.cmd_init("demo", str(tmp_path), "standard", [], None, [], "run-77")
    assert run_metadata.main(["set-codeql", "--enable"]) == 1  # not declared open source
    assert run_metadata.main(["set-codeql", "--enable", "--open-source", "--declared-by", "benchmark"]) == 0
    meta = json.loads((run / "run-metadata.json").read_text(encoding="utf-8"))
    assert meta["codeql"]["enabled"] and meta["codeql"]["declared_by"] == "benchmark"
    assert not run_metadata.validate_metadata(meta) and T.codeql_enabled(meta)
    assert run_metadata.main(["set-codeql"]) == 0
    assert not T.codeql_enabled(json.loads((run / "run-metadata.json").read_text(encoding="utf-8")))


def test_wrappers_offer_the_codeql_image():
    ps1 = (ROOT / "wrappers" / "framac-docker.ps1").read_text(encoding="utf-8")
    sh = (ROOT / "wrappers" / "framac-docker.sh").read_text(encoding="utf-8")
    derived = (ROOT / "wrappers" / "codeql-derived.Dockerfile").read_text(encoding="utf-8")
    assert "[switch]$CodeQL" in ps1 and "framac.codeql.base" in ps1
    assert "--codeql) CODEQL=1" in sh and "framac.codeql.source" in sh
    assert "COPY --from=codeql /opt/codeql /opt/codeql" in derived and "framac.local-only" in derived
    assert "push" not in sh.split("--codeql) CODEQL=1")[1].split("\nfi\n")[0].replace("never pushed", "")


# ---------------------------------------------------------------------------------------------------
# Fixtures (Docker)
# ---------------------------------------------------------------------------------------------------

FIXTURE_PROJECTS = sorted(
    p for kind in ("reproducers", "seeded") for p in (PHASE0_FIXTURES / kind).iterdir() if (p / "truth.json").is_file()
)


@pytest.mark.unit
@pytest.mark.parametrize("project", FIXTURE_PROJECTS, ids=lambda p: p.name)
def test_trust_truth_is_consistent(project):
    truth = json.loads((project / "truth.json").read_text(encoding="utf-8"))
    t = truth["trust"]
    assert set(t["boundary"]) <= set(t["untrusted"])
    assert all(s and set(s) <= set(T.SOURCE_ORDER) for s in t["untrusted"].values())
    if "functions" in truth:
        assert set(t["untrusted"]) | set(t["trusted"]) == set(truth["functions"])
        assert not set(t["untrusted"]) & set(t["trusted"])


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("project", FIXTURE_PROJECTS, ids=lambda p: p.name)
def test_fixture_trust_matches_the_truth(model_run, tmp_path, project):  # noqa: F811
    truth = json.loads((project / "truth.json").read_text(encoding="utf-8"))
    model = model_run(project, tmp_path / "run", truth["build"])
    assert model["trust"]["threat_model"]["status"] == "no_threat_model"
    assert model["trust"]["codeql"] == {"status": "off"}
    got = {fid: f["trust"] for fid, f in model["functions"].items()}
    want = truth["trust"]
    untrusted = {fid: t["sources"] for fid, t in got.items() if t["value"] == "untrusted"}
    assert untrusted == want["untrusted"]
    assert {fid for fid, t in got.items() if t["boundary"]} == set(want["boundary"])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
