"""
A Phase 0 model rebuilt after the CodeQL run keeps its CodeQL trust facts, and `validate_artifacts.py
run-dir` fails when the facts are in no trust mark (libmodbus run-1: `phase0_model.py run`, rerun after
`trust.py run`, wrote `trust.codeql: {"status": "off"}`; validation passed and the report said
`CodeQL: off`). The fixture is that run's model, facts, metadata and threat model
(tests/fixtures/libmodbus_run1_codeql/README.md). No Docker: the model step runs with the parses
replaced by the recorded model.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

import build_callgraph_dag as bcd
import phase0_model as pm
import trust as T
import validate_artifacts as V
from conftest import ROOT
from test_dag_model_view import _model as _view_model
from test_dag_model_view import target  # noqa: F401 - pytest fixture

pytestmark = pytest.mark.unit

RUN1_FIX = ROOT / "tests" / "fixtures" / "libmodbus_run1_codeql"
REPORTS_REL = Path("workspace") / "reports"
MODEL_FILE = REPORTS_REL / "phase0_model.json"
FACTS_FILE = REPORTS_REL / "codeql_trust.json"
DAG_FILE = REPORTS_REL / "callgraph_dag.json"
TIER_INPUTS = ("value", "source", "boundary")


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1), encoding="utf-8", newline="\n")


def _recorded(name: str):
    return _read(RUN1_FIX / name)


def _metadata() -> dict:
    """The run's metadata, without its snapshot manifest (state/ is not part of the fixture)."""
    meta = _recorded("run-metadata.json")
    for key in ("snapshot_manifest", "snapshot_digest"):
        meta.pop(key)
    return meta


def _bare_model() -> dict:
    """What the parses give `phase0_model.py run` before its trust annotation: the recorded model without trust."""
    model = _recorded("phase0_model.json")
    model.pop("trust")
    for rec in [*model["functions"].values(), *model["units"].values()]:
        rec.pop("trust", None)
    return model


@pytest.fixture
def run1(tmp_path, monkeypatch) -> Path:
    """A run directory in run-1's state before the rebuild: CodeQL enabled, facts `ok`, the threat model supplied."""
    run = tmp_path / "run-1"
    _write(run / "run-metadata.json", _metadata())
    _write(run / "coverage-ledger.json", [])
    _write(run / FACTS_FILE, _recorded("codeql_trust.json"))
    shutil.copyfile(RUN1_FIX / "THREAT_MODEL.md", run / "workspace" / "THREAT_MODEL.md")
    monkeypatch.chdir(run)
    monkeypatch.setattr(pm, "build_model", lambda *args, **kwargs: (_bare_model(), 0))
    return run


def _model_step(capsys) -> tuple[dict, dict]:
    """`phase0_model.py run` in the run directory: (the model it wrote, the summary it printed)."""
    capsys.readouterr()
    assert pm.main(["run", "--state", ""]) == 0
    return _read(MODEL_FILE), json.loads(capsys.readouterr().out)


def _trust_run(capsys, *extra: str) -> dict:
    capsys.readouterr()
    assert T.main(["run", *extra]) == 0
    capsys.readouterr()
    return _read(MODEL_FILE)


def _marks(model: dict) -> dict:
    """Everything trust wrote but the time it ran."""
    block = {k: v for k, v in model["trust"].items() if k != "generated_at"}
    return {
        "functions": {fid: rec["trust"] for fid, rec in model["functions"].items()},
        "units": {name: rec["trust"] for name, rec in model["units"].items()},
        "block": block,
    }


def _with_codeql(model: dict) -> set[str]:
    return {fid for fid, rec in model["functions"].items() if "codeql" in rec["trust"]["sources"]}


def _cli_run_dir(run: Path, capsys) -> tuple[int, list[str]]:
    capsys.readouterr()
    rc = V.main(["run-dir", str(run)])
    return rc, json.loads(capsys.readouterr().out)["errors"]


# ---------------------------------------------------------------------------------------------------
# The rebuild keeps the facts
# ---------------------------------------------------------------------------------------------------


def test_a_model_rebuilt_after_the_codeql_run_keeps_its_facts(run1, capsys):
    facts = _recorded("codeql_trust.json")
    named = {f["function"] for f in facts["facts"]}
    model, summary = _model_step(capsys)
    codeql = model["trust"]["codeql"]
    assert codeql["status"] == "ok", "run-1: the rebuilt model said off"
    assert (codeql["facts"], codeql["unmatched"]) == (13, 6)
    assert codeql["path"] == str(FACTS_FILE) and codeql["sha256"] == T._sha256((run1 / FACTS_FILE).read_bytes())
    assert model["trust"]["summary"]["with_codeql"] == 8
    # Every function a fact names and the model has keeps its `codeql` source, and no other function has one.
    assert _with_codeql(model) == named & set(model["functions"]) and len(_with_codeql(model)) == 8
    # In this run CodeQL only adds a source: what the tiers read is what the run recorded.
    recorded = _recorded("phase0_model.json")["functions"]
    for fid, rec in model["functions"].items():
        old, new = recorded[fid]["trust"], rec["trust"]
        assert {k: new[k] for k in TIER_INPUTS} == {k: old[k] for k in TIER_INPUTS}
        assert [s for s in new["sources"] if s != "codeql"] == old["sources"]
    # The step says what it merged, and the result validates.
    assert summary["trust"]["codeql"] == codeql and summary["trust"]["threat_model"] == "ok"
    assert model["warnings"] == [] and V.validate_phase0_artifacts(run1) == []
    assert _cli_run_dir(run1, capsys) == (0, [])


def test_the_rebuild_merges_exactly_what_trust_run_merges(run1, capsys):
    rebuilt, _ = _model_step(capsys)
    assert _marks(_trust_run(capsys)) == _marks(rebuilt)


def test_the_normal_order_still_validates_and_a_rerun_of_the_model_step_changes_nothing(run1, capsys, monkeypatch):
    # The time of the annotation is the only field of the trust that differs between two runs.
    monkeypatch.setattr(T, "utc_now", lambda: "2026-11-18T01:41:07+00:00")
    facts = run1 / FACTS_FILE
    held = facts.read_bytes()
    facts.unlink()
    first, summary = _model_step(capsys)  # the model, before CodeQL ran
    assert first["trust"]["codeql"] == {"status": "not_run", "path": str(FACTS_FILE)}
    assert summary["trust"]["codeql"]["status"] == "not_run" and not _with_codeql(first)
    assert V.validate_phase0_artifacts(run1) == []
    facts.write_bytes(held)  # codeql_trust.py run
    assert any("trust.py run" in e for e in V.validate_phase0_artifacts(run1))  # the merge is due
    merged = _trust_run(capsys)
    assert merged["trust"]["codeql"]["status"] == "ok" and merged["trust"]["codeql"]["facts"] == 13
    assert V.validate_phase0_artifacts(run1) == []
    before = (run1 / MODEL_FILE).read_bytes()
    again, _ = _model_step(capsys)
    assert again == merged
    assert (run1 / MODEL_FILE).read_bytes() == before


# ---------------------------------------------------------------------------------------------------
# Controls: nothing to merge
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("codeql_block", [None, {"enabled": False, "open_source": True}, {"enabled": True}])
def test_without_the_opt_in_the_model_says_off_and_validates(run1, capsys, codeql_block):
    meta = _metadata()
    recorded = meta.pop("codeql")
    if codeql_block is not None:
        meta["codeql"] = {**recorded, "open_source": False, **codeql_block}
    _write(run1 / "run-metadata.json", meta)
    model, _ = _model_step(capsys)  # holds before the fix too: nothing changes for a run without CodeQL
    assert model["trust"]["codeql"] == {"status": "off"}
    assert not _with_codeql(model) and model["trust"]["summary"]["with_codeql"] == 0
    assert V.validate_phase0_artifacts(run1) == []
    assert _cli_run_dir(run1, capsys) == (0, [])
    # The recorded run-1 model is fine too once the run does not enable CodeQL.
    _write(run1 / MODEL_FILE, _recorded("phase0_model.json"))
    assert V.validate_phase0_artifacts(run1) == []


def test_enabled_without_a_facts_file_is_not_run_and_validates(run1, capsys):
    (run1 / FACTS_FILE).unlink()
    model, summary = _model_step(capsys)
    assert model["trust"]["codeql"] == {"status": "not_run", "path": str(FACTS_FILE)}
    (warning,) = summary["trust"]["warnings"]
    assert warning.startswith("codeql: enabled for the run, but there is no report at ") and "trust.py run" in warning
    assert not _with_codeql(model)
    assert _marks(_trust_run(capsys)) == _marks(model)  # as trust.py run
    assert V.validate_phase0_artifacts(run1) == []
    # Nor is the model run-1 recorded (`off`) an error while there is no fact to lose.
    _write(run1 / MODEL_FILE, _recorded("phase0_model.json"))
    assert V.validate_phase0_artifacts(run1) == []


def test_a_failed_codeql_run_gives_no_fact_and_validates(run1, capsys):
    # What codeql_trust.py writes when the database build fails (collect: status, error, no fact).
    failed = {**_recorded("codeql_trust.json"), "status": "database_failed", "error": "make: *** [all] Error 2"}
    failed["facts"] = []
    _write(run1 / FACTS_FILE, failed)
    model, summary = _model_step(capsys)
    codeql = model["trust"]["codeql"]
    assert codeql["status"] == "database_failed" and "facts" not in codeql
    assert "codeql: status database_failed, its facts are not used" in summary["trust"]["warnings"]
    assert not _with_codeql(model)
    assert _marks(_trust_run(capsys)) == _marks(model)  # as trust.py run
    assert V.validate_phase0_artifacts(run1) == []
    _write(run1 / MODEL_FILE, _recorded("phase0_model.json"))
    assert V.validate_phase0_artifacts(run1) == []


@pytest.mark.parametrize("broken", ["run-metadata.json", str(FACTS_FILE)])
def test_unreadable_codeql_inputs_cost_the_facts_not_the_annotation(run1, capsys, broken):
    (run1 / broken).write_text("{not json", encoding="utf-8")
    model, _ = _model_step(capsys)
    assert all(rec["trust"]["value"] == "untrusted" for rec in model["functions"].values())
    assert model["trust"]["codeql"]["status"] == "off" and not _with_codeql(model)
    (warning,) = model["warnings"]
    assert warning.startswith("trust: annotated without the CodeQL facts (") and "trust.py run" in warning
    errors = V.validate_phase0_artifacts(run1)
    if broken == "run-metadata.json":
        assert errors == []  # the run-dir check reports the metadata itself
        assert any(e.startswith("run-metadata.json: ") for e in V.validate_run_dir(run1))
    else:
        (error,) = errors
        assert error.startswith(f"{MODEL_FILE.as_posix()}: CodeQL is enabled for the run and its facts cannot be read")


# ---------------------------------------------------------------------------------------------------
# The validator catches the inconsistency
# ---------------------------------------------------------------------------------------------------


def test_run_dir_fails_on_the_run1_model_that_lost_its_facts(run1, capsys):
    _write(run1 / MODEL_FILE, _recorded("phase0_model.json"))  # trust.codeql: off, as the 02:41 rebuild left it
    rc, errors = _cli_run_dir(run1, capsys)
    assert rc == 1, "run-1: validate_artifacts.py run-dir passed at the end of Phase 0"
    (error,) = errors
    assert error.startswith(f"{MODEL_FILE.as_posix()}: CodeQL is enabled for the run and ")
    assert "is ok with 25 fact(s)" in error and "trust.codeql.status is 'off'" in error
    assert "run trust.py run, then rebuild the DAG" in error
    assert V.validate_run_dir(run1) == [error]  # the report refuses to say `CodeQL: off`
    # The fix the message names. The recorded threat model is the container's /target path: name the file.
    merged = _trust_run(capsys, "--threat-model", str(Path("workspace") / "THREAT_MODEL.md"))
    assert merged["trust"]["codeql"]["facts"] == 13 and len(_with_codeql(merged)) == 8
    assert _cli_run_dir(run1, capsys) == (0, [])


@pytest.mark.parametrize("status", ["not_run", None])
def test_run_dir_fails_on_any_model_without_the_ok_facts(run1, capsys, status):
    model = _recorded("phase0_model.json")
    if status is None:
        model.pop("trust")  # the annotation failed: `trust: not annotated`
    else:
        model["trust"]["codeql"] = {"status": status, "path": str(FACTS_FILE)}
    _write(run1 / MODEL_FILE, model)
    (error,) = V.validate_phase0_artifacts(run1)
    assert f"trust.codeql.status is {status!r}" in error and "trust.py run" in error


def test_run_dir_fails_when_the_merged_facts_are_not_the_files(run1, capsys):
    model, _ = _model_step(capsys)
    assert V.validate_phase0_artifacts(run1) == []
    facts = _recorded("codeql_trust.json")
    dropped = facts["facts"].pop(0)  # CodeQL ran again and found one flow less
    assert dropped["function"] in model["functions"]
    _write(run1 / FACTS_FILE, facts)
    (error,) = V.validate_phase0_artifacts(run1)
    assert "was merged from another" in error and "trust.py run" in error
    # A model merged before the digest was recorded is checked on its counts.
    model["trust"]["codeql"].pop("sha256")
    _write(run1 / MODEL_FILE, model)
    (error,) = V.validate_phase0_artifacts(run1)
    assert "records 13 fact(s) used and 6 unmatched function(s)" in error and "gives 12 and 6" in error
    _write(run1 / FACTS_FILE, _recorded("codeql_trust.json"))
    assert V.validate_phase0_artifacts(run1) == []


def test_run_dir_fails_on_a_dag_built_before_the_facts_were_merged(run1, capsys, target):  # noqa: F811
    def dag_of(model: dict) -> dict:
        # build_callgraph_dag.py copies the model's trust block into the DAG.
        return bcd.build_dag(target, {**_view_model(), "trust": copy.deepcopy(model["trust"])})

    lost = _recorded("phase0_model.json")
    _write(run1 / DAG_FILE, dag_of(lost))  # the DAG run-1 rebuilt at 02:41: CodeQL off
    merged, _ = _model_step(capsys)
    (error,) = V.validate_phase0_artifacts(run1)
    assert error.startswith(f"{DAG_FILE.as_posix()}: its trust marks were copied from a model whose trust.codeql was ")
    assert '{"status": "off"}' in error and "rebuild the DAG (build_callgraph_dag.py)" in error
    _write(run1 / DAG_FILE, dag_of(merged))
    assert V.validate_phase0_artifacts(run1) == []
    assert _cli_run_dir(run1, capsys) == (0, [])
