"""
R3 (docs/phase0-remediation-plan.md): per-file trust of same-named functions (defect 9), one threat
model shared by trust.py and security_props.py (the path and sha256 the model recorded), an invalid
threat model stopping `security_props.py run`, the self-validation policy of both producers, and the
model-feature helper (phase0_model.model_features) instead of their own field sniffing. Unit tests on
recorded fixtures, no Docker.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

import acsl_ast
import security_props as sp
import trust as T
import workspace_overlay as wo
from phase0_model import MODEL_FEATURES

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "security_props"
pytestmark = pytest.mark.unit


def _session_model() -> dict:
    return json.loads((FIX / "session_model.json").read_text(encoding="utf-8"))


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1), encoding="utf-8", newline="\n")
    return path


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_dir(tmp_path: Path, monkeypatch, threat_file: Path | None) -> Path:
    """A run directory whose model the first annotation gave `threat_file` (None: the search order), as phase0_model.py run does."""
    monkeypatch.chdir(tmp_path)
    model = _session_model()
    T.annotate_model(model, threat_file)
    return _write(tmp_path / "workspace" / "reports" / "phase0_model.json", model)


def _sp_run(model: Path, out: Path) -> int:
    return sp.main(["run", "--model", str(model), "--out", str(out)])


def _last_json(capsys) -> dict:
    text = capsys.readouterr().out
    return json.loads(text[text.index("{") :])


# ---------------------------------------------------------------------------------------------------
# Defect 9: per-file trust
# ---------------------------------------------------------------------------------------------------


def _two_f_model() -> dict:
    """libp.a exports a.c#f; b.c#f is a static helper nothing untrusted reaches."""
    fns = {
        "a.c#f": {"name": "f", "file": "a.c", "units": ["libp.a"], "signature": "int(int)", "external_calls": []},
        "b.c#f": {"name": "f", "file": "b.c", "units": ["libp.a"], "signature": "int(int)", "external_calls": [],
                  "static": True},
    }  # fmt: skip
    return {
        "status": "ok",
        "schema_version": 2,
        "functions": fns,
        "units": {"libp.a": {"kind": "static_lib", "test": False, "entry_points": ["a.c#f"]}},
        "edges": [],
    }


def _dag_workspace(tmp_path: Path, functions: dict) -> Path:
    _write(tmp_path / "workspace" / "reports" / "callgraph_dag.json", {"functions": functions})
    return tmp_path / "workspace"


def test_same_named_functions_keep_their_own_trust(tmp_path):
    trust = T.compute_trust(_two_f_model())["functions"]
    assert trust["a.c#f"]["value"] == "untrusted" and trust["a.c#f"]["boundary"]
    assert trust["b.c#f"]["value"] == "trusted"
    # The DAG keys colliding names `file#name`; each record keeps its own trust.
    ws = _dag_workspace(tmp_path, {
        "a.c#f": {"name": "f", "file": "a.c", "trust": trust["a.c#f"]},
        "b.c#f": {"name": "f", "file": "b.c", "trust": trust["b.c#f"]},
    })  # fmt: skip
    records = acsl_ast.function_trust_records(ws)
    assert acsl_ast.is_trust_boundary(records, "f", "a.c") is True
    assert acsl_ast.is_trust_boundary(records, "f", "b.c") is False
    # Without a file, or with a file no record names, the same-named records merge: untrusted wins.
    assert acsl_ast.is_trust_boundary(records, "f") is True
    assert acsl_ast.is_trust_boundary(records, "f", "elsewhere.c") is True
    # The merge's check: only a.c#f is a trust-boundary entry, and it records its file.
    assert wo._untrusted_entry_metas(ws, None, "f", "b.c") == []
    assert wo._untrusted_entry_metas(ws, None, "f", "a.c") == [
        {"entry_fn": "f", "reachability": "untrusted_surface", "trust_boundary": True, "file": "a.c"}
    ]


def test_trust_boundary_check_skips_another_files_same_named_static():
    entry = {"entry_fn": "f", "reachability": "untrusted_surface", "trust_boundary": True, "file": "a.c"}
    base = "int f(int n) { return n; }\n"
    agent = "/*@ requires n < 10; */\nint f(int n) { return n; }\n"
    assert wo.entry_trust_boundary_errors(entry, "a.c", agent, agent, base, base)
    assert wo.entry_trust_boundary_errors(entry, "b.c", agent, agent, base, base) == []
    # A sidecar entry (no file) is checked wherever the agent changed its contract, as before.
    sidecar = {k: v for k, v in entry.items() if k != "file"}
    assert wo.entry_trust_boundary_errors(sidecar, "b.c", agent, agent, base, base)


# ---------------------------------------------------------------------------------------------------
# Invalid and missing threat models
# ---------------------------------------------------------------------------------------------------


def test_an_invalid_threat_model_stops_security_props(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "THREAT_MODEL.md"
    text = (FIX / "secret_unwiped" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    bad.write_text(text.replace('"schema_version": 1', '"schema_version": 7'), encoding="utf-8", newline="\n")
    model = _run_dir(tmp_path, monkeypatch, bad)
    assert _read(model)["trust"]["threat_model"]["status"] == T.STATUS_INVALID
    out = tmp_path / "workspace" / "reports" / "security_props.json"
    capsys.readouterr()
    assert _sp_run(model, out) == 2
    res = _last_json(capsys)
    assert res["ok"] is False and res["threat_model"] == T.STATUS_INVALID and res["errors"]
    assert not out.exists()


def test_a_missing_threat_model_gives_layer_3_only(tmp_path, monkeypatch):
    model = _run_dir(tmp_path, monkeypatch, tmp_path / "absent.md")
    out = tmp_path / "workspace" / "reports" / "security_props.json"
    assert _sp_run(model, out) == 0
    doc = _read(out)
    assert doc["threat_model"]["status"] == T.STATUS_NONE and doc["properties"] == []
    assert [f["function"] for f in doc["frame"]] == ["session.c#session_copy_state"]


def test_a_threat_model_that_appeared_after_the_model_is_refused(tmp_path, monkeypatch, capsys):
    model = _run_dir(tmp_path, monkeypatch, tmp_path / "absent.md")
    shutil.copyfile(FIX / "secret_unwiped" / "THREAT_MODEL.md", tmp_path / "workspace" / "THREAT_MODEL.md")
    capsys.readouterr()
    assert _sp_run(model, tmp_path / "props.json") == 1
    assert "appeared" in _last_json(capsys)["error"]


# ---------------------------------------------------------------------------------------------------
# One threat model: the recorded path and sha256
# ---------------------------------------------------------------------------------------------------


def test_an_edited_threat_model_is_refused_until_the_model_is_rebuilt(tmp_path, monkeypatch, capsys):
    tm = tmp_path / "workspace" / "THREAT_MODEL.md"
    tm.parent.mkdir(parents=True)
    shutil.copyfile(FIX / "secret_unwiped" / "THREAT_MODEL.md", tm)
    model = _run_dir(tmp_path, monkeypatch, None)  # found by the search order
    assert _read(model)["trust"]["threat_model"]["path"] == str(Path("workspace") / "THREAT_MODEL.md")
    out = tmp_path / "workspace" / "reports" / "security_props.json"
    assert _sp_run(model, out) == 0
    first = _read(out)
    assert first["threat_model"]["status"] == "ok" and first["properties"]

    tm.write_text(tm.read_text(encoding="utf-8") + "\nEdited prose.\n", encoding="utf-8", newline="\n")
    capsys.readouterr()
    assert _sp_run(model, out) == 1
    assert "changed since the model was built" in _last_json(capsys)["error"]
    assert _read(out) == first  # nothing written
    # trust.py run (a CodeQL re-run) refuses it too, and leaves the model alone.
    before = _read(model)
    assert T.main(["run", "--model", str(model), "--metadata", str(tmp_path / "none.json")]) == 1
    assert "changed since the model was built" in _last_json(capsys)["error"]
    assert _read(model) == before

    # Rebuilding the model's trust with the edited file records its new sha256.
    rebuilt = _read(model)
    T.annotate_model(rebuilt, None)
    _write(model, rebuilt)
    assert _sp_run(model, out) == 0
    assert _read(out)["threat_model"]["sha256"] == rebuilt["trust"]["threat_model"]["sha256"]
    assert T.main(["run", "--model", str(model), "--metadata", str(tmp_path / "none.json")]) == 0


def test_a_missing_recorded_threat_model_is_refused(tmp_path, monkeypatch, capsys):
    tm = tmp_path / "custom" / "TM.md"
    tm.parent.mkdir()
    shutil.copyfile(FIX / "secret_unwiped" / "THREAT_MODEL.md", tm)
    model = _run_dir(tmp_path, monkeypatch, tm)
    tm.unlink()
    capsys.readouterr()
    assert _sp_run(model, tmp_path / "props.json") == 1
    assert "is missing" in _last_json(capsys)["error"]


def test_a_threat_model_outside_the_search_order_is_honored_downstream(tmp_path, monkeypatch, capsys):
    custom = tmp_path / "elsewhere" / "session-threats.md"
    custom.parent.mkdir()
    shutil.copyfile(FIX / "secret_unwiped" / "THREAT_MODEL.md", custom)
    # A different file where the search order looks first: downstream must not pick it up.
    decoy = tmp_path / "workspace" / "THREAT_MODEL.md"
    decoy.parent.mkdir(parents=True)
    decoy.write_text("# Threat model\n\nNo structured block.\n", encoding="utf-8", newline="\n")
    model = _run_dir(tmp_path, monkeypatch, custom)  # phase0_model.py run --threat-model <custom>
    recorded = _read(model)["trust"]["threat_model"]
    assert recorded["path"] == str(custom) and recorded["status"] == "ok"

    out = tmp_path / "workspace" / "reports" / "security_props.json"
    assert _sp_run(model, out) == 0
    doc = _read(out)
    assert doc["threat_model"]["path"] == str(custom) and doc["threat_model"]["sha256"] == recorded["sha256"]
    assert {p["kind"] for p in doc["properties"]} >= {"auth_state", "sanitized", "wiped"}

    # trust.py run (CodeQL re-run) keeps the recorded file, not the decoy.
    capsys.readouterr()
    assert T.main(["run", "--model", str(model), "--metadata", str(tmp_path / "none.json")]) == 0
    assert _read(model)["trust"]["threat_model"]["path"] == str(custom)
    # An explicit --threat-model is a new choice, which the model then records.
    assert T.main(["run", "--model", str(model), "--threat-model", str(decoy)]) == 0
    assert _read(model)["trust"]["threat_model"]["path"] == str(decoy)
    assert _sp_run(model, out) == 0
    assert _read(out)["threat_model"]["status"] == T.STATUS_NONE


# ---------------------------------------------------------------------------------------------------
# Self-validation
# ---------------------------------------------------------------------------------------------------


def test_security_props_records_its_schema_problems_as_warnings(tmp_path, monkeypatch, capsys):
    model = _run_dir(tmp_path, monkeypatch, tmp_path / "absent.md")
    monkeypatch.setattr(sp, "validate", lambda doc: ["properties: broken"])
    out = tmp_path / "props.json"
    capsys.readouterr()
    assert _sp_run(model, out) == 0
    assert any(w.startswith("schema: ") and "broken" in w for w in _read(out)["warnings"])
    assert _last_json(capsys)["schema"] == ["properties: broken"]


def test_trust_run_validates_the_model_it_rewrites(tmp_path, monkeypatch, capsys):
    model = _run_dir(tmp_path, monkeypatch, tmp_path / "absent.md")
    data = _read(model)
    data["warnings"] = ["schema: ['stale']", "kept"]
    data.setdefault("generated_at", "2026-11-08T00:00:00Z")  # the recorded fixture predates the field
    _write(model, data)
    assert T.main(["run", "--model", str(model), "--metadata", str(tmp_path / "none.json")]) == 0
    assert _read(model)["warnings"] == ["kept"]  # valid: the stale schema warning goes
    monkeypatch.setattr(T, "validate_model", lambda m: ["functions: broken"])
    capsys.readouterr()
    assert T.main(["run", "--model", str(model), "--metadata", str(tmp_path / "none.json")]) == 0
    assert _read(model)["warnings"] == ["kept", "schema: ['functions: broken']"]
    assert _last_json(capsys)["schema"] == ["functions: broken"]


# ---------------------------------------------------------------------------------------------------
# Version checks through phase0_model.model_features
# ---------------------------------------------------------------------------------------------------


def _strip(model: dict, *fields: str) -> dict:
    out = copy.deepcopy(model)
    out.pop("schema_version", None)
    for f in out["functions"].values():
        for field in fields:
            f.pop(field, None)
    return out


def test_a_version_1_model_missing_features_warns_through_model_features():
    old = _strip(_session_model(), "external_calls", "formals", "writes")
    doc = sp.generate(old, None)
    for feature in ("external_calls", "formals", "writes"):
        assert f"the model has {MODEL_FEATURES[feature]}" in doc["warnings"]
    # Without write facts, L3 falls back to pointer parameters.
    assert any("no write facts in the model" in f["reason"] for f in doc["frame"])
    assert any("external calls" in w for w in T.compute_trust(old)["warnings"])


def test_a_version_2_model_has_its_features_by_version():
    model = _two_f_model()  # schema_version 2: no field sniffing
    for f in model["functions"].values():
        f.pop("external_calls")
    assert not any("external calls" in w for w in T.compute_trust(model)["warnings"])
    assert not [w for w in sp.generate(model, None)["warnings"] if w.startswith("the model has")]
    model.pop("schema_version")
    assert any("external calls" in w for w in T.compute_trust(model)["warnings"])


def test_a_model_without_the_trust_feature_searches_and_trust_run_records_it(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    model = _session_model()
    model.pop("trust")
    for f in model["functions"].values():
        f.pop("trust", None)
    path = _write(tmp_path / "workspace" / "reports" / "phase0_model.json", model)
    shutil.copyfile(FIX / "secret_unwiped" / "THREAT_MODEL.md", tmp_path / "workspace" / "THREAT_MODEL.md")
    # Without the trust feature there is no record: security_props looks it up as trust.py does, and says so.
    assert _sp_run(path, tmp_path / "props.json") == 0
    warnings = _read(tmp_path / "props.json")["warnings"]
    assert warnings[0].startswith(f"the model has {MODEL_FEATURES['trust']}")
    assert _read(tmp_path / "props.json")["threat_model"]["status"] == "ok"
    assert T.main(["run", "--model", str(path), "--metadata", str(tmp_path / "none.json")]) == 0
    assert _read(path)["trust"]["threat_model"]["status"] == "ok"
    assert _sp_run(path, tmp_path / "props.json") == 0
